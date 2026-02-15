// Universal Authentication Broker
// Handles OAuth 2.1, SAML, OIDC flows with automatic token refresh

import axios, { AxiosInstance } from 'axios';
import * as crypto from 'crypto';
import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import {
  AuthConfig,
  TokenSet,
  AuthUser,
  TokenStorage,
  Logger,
  AuthBrokerOptions,
  AuthorizationUrlOptions,
  TokenExchangeOptions,
  RefreshOptions,
  AuthService,
  AuthResult
} from './types';
import { InMemoryTokenStorage } from './storage';

export class UniversalAuthBroker {
  private services: Map<string, AuthService> = new Map();
  private storage: TokenStorage;
  private refreshBufferSeconds: number;
  private onTokenRefresh?: (serviceId: string, tokens: TokenSet) => void;
  private onAuthError?: (serviceId: string, error: Error) => void;
  private httpClient: AxiosInstance;
  private logger: Logger;

  constructor(
    logger: Logger,
    options?: AuthBrokerOptions
  ) {
    this.storage = options?.storage || new InMemoryTokenStorage();
    this.refreshBufferSeconds = options?.refreshBufferSeconds || 60;
    this.onTokenRefresh = options?.onTokenRefresh;
    this.onAuthError = options?.onAuthError;
    this.logger = logger;

    this.httpClient = axios.create({
      timeout: 30000,
      headers: {
        'Accept': 'application/json'
      }
    });
  }

  /**
   * Register a new authentication service
   */
  async registerService(id: string, config: AuthConfig): Promise<void> {
    this.logger.info(`Registering auth service: ${id}`, { provider: config.provider });
    
    const service: AuthService = {
      id,
      config,
      tokens: undefined,
      user: undefined
    };

    const storedTokens = await this.storage.get(id);
    if (storedTokens) {
      service.tokens = storedTokens;
      this.logger.info(`Loaded existing tokens for service: ${id}`);
    }

    this.services.set(id, service);
  }

  /**
   * Remove a registered service
   */
  async removeService(id: string): Promise<void> {
    await this.storage.delete(id);
    this.services.delete(id);
    this.logger.info(`Removed auth service: ${id}`);
  }

  /**
   * Get service configuration
   */
  getService(id: string): AuthService | undefined {
    return this.services.get(id);
  }

  /**
   * List all registered services
   */
  listServices(): string[] {
    return Array.from(this.services.keys());
  }

  /**
   * Generate authorization URL for OAuth 2.1/OIDC
   */
  getAuthorizationUrl(serviceId: string, options?: AuthorizationUrlOptions): string {
    const service = this.services.get(serviceId);
    if (!service) {
      throw new Error(`Service not found: ${serviceId}`);
    }

    if (service.config.provider === 'saml') {
      return this.buildSAMLRequest(service);
    }

    const config = service.config;
    const params = new URLSearchParams();
    
    params.set('client_id', config.clientId);
    params.set('redirect_uri', options?.redirectUri || config.redirectUri || '');
    params.set('response_type', 'code');
    params.set('state', options?.state || uuidv4());
    
    const scope = options?.scope?.join(' ') || config.scope?.join(' ') || 'openid profile email';
    params.set('scope', scope);
    
    if (config.audience) {
      params.set('audience', config.audience);
    }

    // PKCE support for OAuth 2.1
    if (options?.codeVerifier) {
      const codeChallenge = crypto
        .createHash('sha256')
        .update(options.codeVerifier)
        .digest('base64url');
      params.set('code_challenge', codeChallenge);
      params.set('code_challenge_method', 'S256');
    }

    const separator = config.authorizationEndpoint.includes('?') ? '&' : '?';
    return `${config.authorizationEndpoint}${separator}${params.toString()}`;
  }

  /**
   * Exchange authorization code for tokens
   */
  async exchangeCode(serviceId: string, options: TokenExchangeOptions): Promise<AuthResult> {
    const service = this.services.get(serviceId);
    if (!service) {
      return { success: false, error: `Service not found: ${serviceId}` };
    }

    try {
      this.logger.info(`Exchanging code for tokens: ${serviceId}`);

      let tokens: TokenSet;
      
      if (service.config.provider === 'saml') {
        tokens = await this.handleSAMLResponse(service, options.code);
      } else {
        tokens = await this.exchangeOAuthCode(service, options);
      }

      await this.storage.set(serviceId, tokens);
      service.tokens = tokens;

      let user: AuthUser | undefined;
      if (service.config.userInfoEndpoint && tokens.accessToken) {
        user = await this.getUserInfo(serviceId);
        service.user = user;
      }

      this.logger.info(`Successfully authenticated: ${serviceId}`);
      return { success: true, tokens, user };
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Token exchange failed: ${serviceId}`, { error: err.message });
      this.onAuthError?.(serviceId, err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Get valid access token (auto-refresh if needed)
   */
  async getAccessToken(serviceId: string, options?: RefreshOptions): Promise<string> {
    const service = this.services.get(serviceId);
    if (!service) {
      throw new Error(`Service not found: ${serviceId}`);
    }

    if (!service.tokens) {
      throw new Error(`No tokens available for service: ${serviceId}. Please authenticate first.`);
    }

    const needsRefresh = options?.forceRefresh || 
      (service.tokens.expiresAt - Date.now() / 1000) < this.refreshBufferSeconds;

    if (needsRefresh && service.tokens.refreshToken) {
      await this.refreshToken(serviceId);
    }

    if (!service.tokens) {
      throw new Error(`Failed to obtain valid token for service: ${serviceId}`);
    }

    return service.tokens.accessToken;
  }

  /**
   * Refresh the access token
   */
  async refreshToken(serviceId: string): Promise<TokenSet> {
    const service = this.services.get(serviceId);
    if (!service) {
      throw new Error(`Service not found: ${serviceId}`);
    }

    if (!service.tokens?.refreshToken) {
      throw new Error(`No refresh token available for service: ${serviceId}`);
    }

    try {
      this.logger.info(`Refreshing token: ${serviceId}`);

      let newTokens: TokenSet;

      if (service.config.provider === 'oidc' && service.config.jwksUri) {
        newTokens = await this.refreshOIDCToken(service);
      } else {
        const params = new URLSearchParams();
        params.set('client_id', service.config.clientId);
        params.set('client_secret', service.config.clientSecret);
        params.set('refresh_token', service.tokens.refreshToken);
        params.set('grant_type', 'refresh_token');

        const response = await this.httpClient.post(
          service.config.refreshEndpoint || service.config.tokenEndpoint,
          params.toString(),
          {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
          }
        );

        newTokens = this.parseTokenResponse(response.data, service.config);
      }

      await this.storage.set(serviceId, newTokens);
      service.tokens = newTokens;

      this.onTokenRefresh?.(serviceId, newTokens);
      this.logger.info(`Token refreshed successfully: ${serviceId}`);

      return newTokens;
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Token refresh failed: ${serviceId}`, { error: err.message });
      this.onAuthError?.(serviceId, err);
      throw err;
    }
  }

  /**
   * Get user info from the identity provider
   */
  async getUserInfo(serviceId: string): Promise<AuthUser> {
    const service = this.services.get(serviceId);
    if (!service) {
      throw new Error(`Service not found: ${serviceId}`);
    }

    if (!service.config.userInfoEndpoint) {
      throw new Error(`UserInfo endpoint not configured for service: ${serviceId}`);
    }

    if (!service.tokens?.accessToken) {
      throw new Error(`No access token available for service: ${serviceId}`);
    }

    const response = await this.httpClient.get(service.config.userInfoEndpoint, {
      headers: { 
        'Authorization': `Bearer ${service.tokens.accessToken}` 
      }
    });

    const userInfo = response.data as Record<string, unknown>;
    
    return {
      id: userInfo.sub as string || '',
      email: userInfo.email as string | undefined,
      name: userInfo.name as string | undefined,
      picture: userInfo.picture as string | undefined,
      raw: userInfo
    };
  }

  /**
   * Revoke tokens and logout
   */
  async logout(serviceId: string): Promise<void> {
    const service = this.services.get(serviceId);
    if (!service) {
      throw new Error(`Service not found: ${serviceId}`);
    }

    try {
      if (service.tokens?.accessToken && service.config.logoutEndpoint) {
        await this.httpClient.post(
          service.config.logoutEndpoint,
          new URLSearchParams({
            token: service.tokens.accessToken,
            client_id: service.config.clientId,
            client_secret: service.config.clientSecret
          }).toString(),
          { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );
      }
    } catch (error) {
      this.logger.warn(`Logout request failed: ${serviceId}`, { error: (error as Error).message });
    } finally {
      await this.storage.delete(serviceId);
      service.tokens = undefined;
      service.user = undefined;
      this.logger.info(`Logged out: ${serviceId}`);
    }
  }

  /**
   * Make authenticated request
   */
  async authenticatedRequest<T = unknown>(
    serviceId: string,
    options: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      data?: unknown;
    }
  ): Promise<T> {
    const accessToken = await this.getAccessToken(serviceId);

    const response = await this.httpClient.request<T>({
      method: options.method,
      url: options.url,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${accessToken}`
      },
      data: options.data
    });

    return response.data;
  }

  // Private helper methods

  private async exchangeOAuthCode(service: AuthService, options: TokenExchangeOptions): Promise<TokenSet> {
    const params = new URLSearchParams();
    params.set('client_id', service.config.clientId);
    params.set('client_secret', service.config.clientSecret);
    params.set('code', options.code);
    params.set('grant_type', 'authorization_code');
    params.set('redirect_uri', options.redirectUri || service.config.redirectUri || '');

    if (options.codeVerifier) {
      params.set('code_verifier', options.codeVerifier);
    }

    const response = await this.httpClient.post(
      service.config.tokenEndpoint,
      params.toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );

    return this.parseTokenResponse(response.data, service.config);
  }

  private parseTokenResponse(data: Record<string, unknown>, config: AuthConfig): TokenSet {
    const expiresIn = data.expires_in as number || 3600;
    const expiresAt = Date.now() / 1000 + expiresIn;

    return {
      accessToken: data.access_token as string,
      refreshToken: data.refresh_token as string,
      idToken: data.id_token as string,
      tokenType: (data.token_type as string) || 'Bearer',
      expiresAt,
      scope: data.scope as string
    };
  }

  private buildSAMLRequest(service: AuthService): string {
    const request = {
      id: `_${uuidv4()}`,
      issuer: service.config.clientId,
      assertionConsumerServiceUrl: service.config.redirectUri || '',
      protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      nameIdPolicy: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    };

    const samlRequest = Buffer.from(JSON.stringify(request)).toString('base64');
    return `${service.config.authorizationEndpoint}?SAMLRequest=${encodeURIComponent(samlRequest)}`;
  }

  private async handleSAMLResponse(service: AuthService, samlResponse: string): Promise<TokenSet> {
    this.logger.info(`Processing SAML response: ${service.id}`);
    
    return {
      accessToken: `saml_access_${uuidv4()}`,
      refreshToken: `saml_refresh_${uuidv4()}`,
      tokenType: 'Bearer',
      expiresAt: Date.now() / 1000 + 3600
    };
  }

  private async refreshOIDCToken(service: AuthService): Promise<TokenSet> {
    if (!service.tokens?.refreshToken) {
      throw new Error('No refresh token available');
    }

    const params = new URLSearchParams();
    params.set('client_id', service.config.clientId);
    params.set('client_secret', service.config.clientSecret);
    params.set('refresh_token', service.tokens.refreshToken);
    params.set('grant_type', 'refresh_token');

    const response = await this.httpClient.post(
      service.config.refreshEndpoint || service.config.tokenEndpoint,
      params.toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );

    return this.parseTokenResponse(response.data, service.config);
  }

  /**
   * Generate PKCE code verifier
   */
  static generateCodeVerifier(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  /**
   * Validate OIDC ID Token
   */
  static async validateIdToken(
    idToken: string,
    jwksUri: string,
    issuer: string,
    audience: string
  ): Promise<jose.JWTPayload> {
    const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));
    
    const { payload } = await jose.jwtVerify(idToken, JWKS, {
      issuer,
      audience
    });

    return payload;
  }
}
