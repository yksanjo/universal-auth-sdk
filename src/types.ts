// Types for Universal Auth SDK

export interface AuthConfig {
  provider: 'oauth2' | 'saml' | 'oidc';
  clientId: string;
  clientSecret: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  refreshEndpoint?: string;
  userInfoEndpoint?: string;
  issuer?: string;
  scope?: string[];
  audience?: string;
  jwksUri?: string;
  cert?: string;
  redirectUri?: string;
  logoutEndpoint?: string;
}

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType: string;
  expiresAt: number;
  scope?: string;
}

export interface AuthUser {
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  roles?: string[];
  groups?: string[];
  raw: Record<string, unknown>;
}

export interface TokenStorage {
  get(serviceId: string): Promise<TokenSet | null>;
  set(serviceId: string, tokens: TokenSet): Promise<void>;
  delete(serviceId: string): Promise<void>;
  clear(): Promise<void>;
}

export interface Logger {
  info: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, meta?: Record<string, unknown>) => void;
  debug: (message: string, meta?: Record<string, unknown>) => void;
}

export interface AuthBrokerOptions {
  storage?: TokenStorage;
  refreshBufferSeconds?: number;
  onTokenRefresh?: (serviceId: string, tokens: TokenSet) => void;
  onAuthError?: (serviceId: string, error: Error) => void;
}

export interface AuthorizationUrlOptions {
  state?: string;
  nonce?: string;
  codeVerifier?: string;
  redirectUri?: string;
  scope?: string[];
}

export interface TokenExchangeOptions {
  code: string;
  redirectUri?: string;
  codeVerifier?: string;
}

export interface RefreshOptions {
  forceRefresh?: boolean;
}

export interface AuthService {
  id: string;
  config: AuthConfig;
  tokens?: TokenSet;
  user?: AuthUser;
}

export interface AuthResult {
  success: boolean;
  tokens?: TokenSet;
  user?: AuthUser;
  error?: string;
  state?: string;
}
