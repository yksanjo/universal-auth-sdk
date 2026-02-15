// Logger implementation

import winston from 'winston';
import { Logger } from './types';

export type { Logger };

export function createLogger(options?: {
  level?: string;
  silent?: boolean;
}): Logger {
  const logger = winston.createLogger({
    level: options?.level || 'info',
    silent: options?.silent || false,
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    defaultMeta: { service: 'universal-auth-sdk' },
    transports: [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      })
    ]
  });

  return {
    info: (message: string, meta?: Record<string, unknown>) => {
      logger.info(message, meta);
    },
    warn: (message: string, meta?: Record<string, unknown>) => {
      logger.warn(message, meta);
    },
    error: (message: string, meta?: Record<string, unknown>) => {
      logger.error(message, meta);
    },
    debug: (message: string, meta?: Record<string, unknown>) => {
      logger.debug(message, meta);
    }
  };
}

export const defaultLogger = createLogger();
