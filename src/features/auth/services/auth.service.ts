import { CACHE_MANAGER } from "@nestjs/cache-manager";
import {
  ConflictException,
  HttpException,
  Inject,
  Injectable,
  NotAcceptableException,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { JwtService } from "@nestjs/jwt";
import bcrypt from "bcryptjs";
import { Cache } from "cache-manager";

import { ValidationException } from "~/common/exceptions/validation.exception";
import { authConfig } from "~/configs";
import { UserService } from "~/features/user/user.service";

import {
  ResendVerifyLinkEvent,
  SendPasswordResetLinkEvent,
  UserRegisteredEvent,
} from "../auth.events";
import {
  RESEND_VERIFY_LINK,
  SEND_PASSWORD_RESET_LINK,
  USER_REGISTERED,
} from "../auth.listeners";
import { ResetPasswordDto } from "../dto/reset-password.dto";
import { UserRegisterDto } from "../dto/user-register.dto";

@Injectable()
export class AuthService {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    @Inject(authConfig.KEY) private authConfig: Configs["auth"],
    private userService: UserService,
    private jwtService: JwtService,
    private eventEmitter: EventEmitter2
  ) {}

  async register(dto: UserRegisterDto) {
    try {
      const { email } = dto;
      const user = await this.userService.create(dto);
      const token = await this.cacheManager.wrap(
        `verify-token.email=${email}`,
        async () => {
          return this.jwtService.sign(
            { email },
            {
              secret: this.authConfig.confirmTokenSecret,
              expiresIn: this.authConfig.confirmTokenExpires + "s",
            }
          );
        },
        this.authConfig.confirmTokenExpires * 1000
      );

      this.eventEmitter.emitAsync(
        USER_REGISTERED,
        new UserRegisteredEvent({
          id: user.id,
          email,
          token,
        })
      );
    } catch (error) {
      if (error instanceof ConflictException)
        throw new ValidationException("email", error.message);

      throw error;
    }
  }

  async sendVerifyLink(email: string) {
    const user = await this.userService.findByEmail(email);
    if (user.isVerified)
      throw new ValidationException("email", "Already verified");

    const prevToken = await this.cacheManager.get(
      `verify-token.email=${email}`
    );
    if (prevToken) {
      return {
        message: `Email verification link already sent, try again after ${this.authConfig.confirmTokenExpires / 60} minutes`,
      };
    }

    const token = await this.cacheManager.wrap(
      `verify-token.email=${email}`,
      async () => {
        return this.jwtService.sign(
          { email },
          {
            secret: this.authConfig.confirmTokenSecret,
            expiresIn: this.authConfig.confirmTokenExpires + "s",
          }
        );
      },
      this.authConfig.confirmTokenExpires * 1000
    );

    this.eventEmitter.emitAsync(
      RESEND_VERIFY_LINK,
      new ResendVerifyLinkEvent({
        token,
        email,
        id: user.id,
      })
    );

    return { message: `Email verification link has been sent to "${email}"` };
  }

  async verifyEmail(token: string) {
    try {
      const { email } = this.jwtService.verify(token, {
        secret: this.authConfig.confirmTokenSecret,
      });

      const cachedVerifyToken = await this.cacheManager.get(
        `verify-token.email=${email}`
      );
      if (!cachedVerifyToken || cachedVerifyToken !== token) {
        throw new HttpException("Invalid link", 400);
      }

      const user = await this.userService.findByEmail(email);
      if (!user) throw new NotAcceptableException();

      await this.userService.update(user.id, { isVerified: true });

      this.cacheManager.del(`verify-token.email=${email}`);
    } catch (error) {
      if (!(error instanceof Error)) {
        throw error;
      }

      if (
        error.name === "JsonWebTokenError" ||
        error.name === "TokenExpiredError"
      ) {
        throw new HttpException("Invalid link", 400);
      }

      throw error;
    }
  }

  async login(email: string, password: string) {
    try {
      const user = await this.userService.findByEmail(email);
      // if user registered with google, then restrict login with google email
      if (!user.password)
        throw new ValidationException("email", "User not found");

      if (!user.isVerified) {
        return await this.sendVerifyLink(email);
      }

      if (!bcrypt.compareSync(password, user.password)) {
        throw new ValidationException("password", "Invalid password");
      }

      const { accessToken, refreshToken } = this.generateAuthTokens(user.email);

      return {
        accessToken,
        refreshToken,
        user: user,
      } satisfies AuthResponse;
    } catch (error) {
      if (error instanceof NotFoundException)
        throw new ValidationException("email", "User not found");

      throw error;
    }
  }

  async refreshAccessToken(refreshToken: string) {
    try {
      const { email } = this.jwtService.verify<AccessTokenPayload>(
        refreshToken,
        {
          secret: this.authConfig.refreshTokenSecret,
        }
      );

      const user = await this.userService.findByEmail(email);
      if (!user) throw new UnauthorizedException();

      return this.jwtService.sign({ email: user.email } as AccessTokenPayload);
    } catch (error) {
      if (!(error instanceof Error)) {
        throw error;
      }

      if (
        error.name === "JsonWebTokenError" ||
        error.name === "TokenExpiredError"
      ) {
        throw new UnauthorizedException();
      }

      throw error;
    }
  }

  async sendPasswordResetLink(email: string) {
    const cachedToken = await this.cacheManager.get(
      `reset-password-token.email=${email}`
    );

    if (cachedToken)
      return {
        message: `Reset link already sent, try again after ${this.authConfig.resetPasswordTokenExpires / 60} minutes`,
      };

    try {
      const user = await this.userService.findByEmail(email);
      if (!user.isVerified)
        throw new ValidationException("email", "Email not verified!");

      const token = await this.cacheManager.wrap(
        `reset-password-token.email=${email}`,
        async () => {
          return this.jwtService.sign(
            { email },
            {
              secret: this.authConfig.resetPasswordTokenSecret,
              expiresIn: this.authConfig.resetPasswordTokenExpires + "s",
            }
          );
        },
        this.authConfig.resetPasswordTokenExpires * 1000
      );

      this.eventEmitter.emitAsync(
        SEND_PASSWORD_RESET_LINK,
        new SendPasswordResetLinkEvent({
          token,
          email: user.email,
          username: user.username,
        })
      );

      return { message: `A password reset link has been sent to "${email}"` };
    } catch (error) {
      if (error instanceof NotFoundException)
        throw new ValidationException("email", "User not found");

      throw error;
    }
  }

  async resetPassword(dto: ResetPasswordDto) {
    try {
      const { email } = this.jwtService.verify(dto.token, {
        secret: this.authConfig.resetPasswordTokenSecret,
      });

      const cachedToken = await this.cacheManager.get(
        `reset-password-token.email=${email}`
      );
      if (!cachedToken || cachedToken !== dto.token) {
        throw new HttpException("Invalid link", 400);
      }

      const user = await this.userService.findByEmail(email);

      await this.userService.update(user.id, { password: dto.password });

      this.cacheManager.del(`reset-password-token.email=${email}`);
    } catch (error) {
      // console.log(error)
      if (!(error instanceof Error)) {
        throw error;
      }

      if (
        error.name === "JsonWebTokenError" ||
        error.name === "TokenExpiredError"
      ) {
        throw new HttpException("Invalid link", 400);
      }

      throw error;
    }
  }

  private generateAuthTokens(email: string) {
    const payload: AccessTokenPayload = { email };
    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.authConfig.refreshTokenSecret,
      expiresIn: this.authConfig.refreshTokenExpires + "s",
    });

    return { accessToken, refreshToken };
  }
}
