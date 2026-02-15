// In-Memory Token Storage

import { TokenStorage, TokenSet } from './types';

export class InMemoryTokenStorage implements TokenStorage {
  private tokens: Map<string, TokenSet> = new Map();

  async get(serviceId: string): Promise<TokenSet | null> {
    return this.tokens.get(serviceId) || null;
  }

  async set(serviceId: string, tokens: TokenSet): Promise<void> {
    this.tokens.set(serviceId, { ...tokens });
  }

  async delete(serviceId: string): Promise<void> {
    this.tokens.delete(serviceId);
  }

  async clear(): Promise<void> {
    this.tokens.clear();
  }
}

// File-based token storage (for persistence)
export class FileTokenStorage implements TokenStorage {
  private filepath: string;
  private cache: Map<string, TokenSet> = new Map();
  private loaded = false;

  constructor(filepath: string) {
    this.filepath = filepath;
  }

  private async load(): Promise<void> {
    if (this.loaded) return;
    
    try {
      const fs = await import('fs/promises');
      const data = await fs.readFile(this.filepath, 'utf-8');
      const parsed = JSON.parse(data);
      this.cache = new Map(Object.entries(parsed));
      this.loaded = true;
    } catch {
      this.cache = new Map();
      this.loaded = true;
    }
  }

  private async persist(): Promise<void> {
    const fs = await import('fs/promises');
    const data = JSON.stringify(Object.fromEntries(this.cache), null, 2);
    await fs.writeFile(this.filepath, data, 'utf-8');
  }

  async get(serviceId: string): Promise<TokenSet | null> {
    await this.load();
    const token = this.cache.get(serviceId);
    return token ? { ...token } : null;
  }

  async set(serviceId: string, tokens: TokenSet): Promise<void> {
    await this.load();
    this.cache.set(serviceId, { ...tokens });
    await this.persist();
  }

  async delete(serviceId: string): Promise<void> {
    await this.load();
    this.cache.delete(serviceId);
    await this.persist();
  }

  async clear(): Promise<void> {
    this.cache.clear();
    await this.persist();
  }
}
