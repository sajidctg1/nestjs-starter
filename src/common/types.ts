import type {
  NextFunction,
  Request as ExpressRequest,
  Response as ExpressResponse,
} from "express";
import type { ObjectLiteral } from "typeorm";

import { type IConfig } from "~/core/config/config.module";
import type { UserEntity } from "~/features/user/entities/user.entity";

import type { CursorPaginationDto } from "./dtos/cursor-pagination.dto";
import type { OffsetPaginationDto } from "./dtos/offset-pagination.dto";

interface IRequest extends ExpressRequest {
  user: UserEntity;
  cookies: Record<string, any>;
}

declare global {
  // Using this allows is to quickly switch between express and fastify and others
  export type NestRequest = IRequest;
  export type NestResponse = ExpressResponse;
  export type NestNextFunction = NextFunction;

  export type Configs = IConfig;

  export type CursorPaginationOptions<T extends ObjectLiteral> =
    CursorPaginationDto & {
      searchField: keyof T;
      cursorField: keyof T;
      cursorType: "string" | "number" | "date";
    };

  export type OffsetPaginationOptions<T extends ObjectLiteral> =
    OffsetPaginationDto & {
      searchField: keyof T;
    };
}

declare module "express-session" {
  interface SessionData {
    passwordConfirmed: boolean;
    emailVerified: boolean;
  }
}
