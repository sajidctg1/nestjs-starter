import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  Inject,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from "@nestjs/common";
import { ApiTags } from "@nestjs/swagger";

import { JWTAuthGuard } from "~/common/guards/auth/jwt-auth.guard";
import { appConfig, authConfig } from "~/configs";

import {
  ACCESS_TOKEN_COOKIE_NAME,
  REFRESH_TOKEN_COOKIE_NAME,
} from "../constants";
import { ForgetPasswordDto } from "../dto/forgot-password.dto";
import { ResetPasswordDto } from "../dto/reset-password.dto";
import { UserLoginDto } from "../dto/user-login.dto";
import { UserRegisterDto } from "../dto/user-register.dto";
import { AuthService } from "../services/auth.service";

@ApiTags("Auth")
@Controller("auth")
export class AuthController {
  constructor(
    @Inject(appConfig.KEY) private appConfig: Configs["app"],
    @Inject(authConfig.KEY) private authConfig: Configs["auth"],
    private authService: AuthService
  ) {}

  @Post("/sign-in")
  async signIn(
    @Body() dto: UserLoginDto,
    @Res({ passthrough: true }) res: NestResponse
  ) {
    const data = await this.authService.login(dto.email, dto.password);

    if ("message" in data) return data;

    res.cookie(ACCESS_TOKEN_COOKIE_NAME, data.accessToken, {
      maxAge: 1000 * this.authConfig.accessTokenExpires,
      httpOnly: true,
      secure: this.appConfig.env === "production",
      path: "/",
    });
    res.cookie(REFRESH_TOKEN_COOKIE_NAME, data.refreshToken, {
      maxAge: 1000 * this.authConfig.refreshTokenExpires,
      httpOnly: true,
      secure: this.appConfig.env === "production",
      path: "/",
    });

    return data.user;
  }

  @Post("/sign-out")
  async signOut(@Res({ passthrough: true }) res: NestResponse) {
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    return { message: "Successfully signout" };
  }

  @Post("/sign-up")
  async signUp(@Req() _req: NestRequest, @Body() dto: UserRegisterDto) {
    await this.authService.register(dto);

    // req.session.emailVerified = false;

    return {
      message: `A email confirmation link has been sent to "${dto.email}"`,
    };
  }

  @Post("/send-verify-email")
  async sendVerifyEmail(@Body() { email }: ForgetPasswordDto) {
    return this.authService.sendVerifyLink(email);
  }

  @Get("/verify-email")
  async verifyEmail(@Query("token") token: string) {
    if (!token) throw new BadRequestException("query string 'token' missing");

    await this.authService.verifyEmail(token);

    return { message: "Email address successfully verifed" };
  }

  @Post("/refresh-token")
  async refreshToken(
    @Req() req: NestRequest,
    @Res({ passthrough: true }) res: NestResponse
  ) {
    if (!req.cookies) throw new ForbiddenException("Cookies missing");

    // @ts-ignore
    const refreshToken = req.headers.authorization || req.cookies.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException(
        "Refresh token must be provided with Authorization header or with cookie"
      );
    }

    const accessToken = await this.authService.refreshAccessToken(refreshToken);

    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * this.authConfig.accessTokenExpires,
      httpOnly: true,
      secure: this.appConfig.env === "production",
      path: "/",
    });

    return { accessToken };
  }

  @Post("/forget-password")
  async forgetPassword(@Body() { email }: ForgetPasswordDto) {
    return this.authService.sendPasswordResetLink(email);
  }

  @Post("/reset-password")
  async resetPassword(@Body() dto: ResetPasswordDto) {
    await this.authService.resetPassword(dto);
    return { message: "Password successfully updated" };
  }

  @Get("/get-session")
  @UseGuards(JWTAuthGuard)
  async getSession(@Req() req: NestRequest) {
    return req.user;
  }
}
