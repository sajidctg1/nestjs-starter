import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";

import { authConfig } from "~/configs";

import { UserModule } from "../user/user.module";
import { AuthEventListener } from "./auth.listeners";
import { TwoFAController } from "./controllers/2fa.controller";
import { AuthController } from "./controllers/auth.controller";
import { TwoFAService } from "./services/2fa.service";
import { AuthService } from "./services/auth.service";
import { JwtStrategy } from "./strategies/jwt.strategy";

@Module({
  controllers: [AuthController, TwoFAController],
  imports: [
    UserModule,
    PassportModule,
    JwtModule.registerAsync({
      inject: [authConfig.KEY],
      useFactory: (config: Configs["auth"]) => ({
        secret: config.accessTokenSecret,
        signOptions: {
          expiresIn: config.accessTokenExpires + "s",
        },
      }),
    }),
  ],
  providers: [JwtStrategy, AuthService, TwoFAService, AuthEventListener],
})
export class AuthModule {}
