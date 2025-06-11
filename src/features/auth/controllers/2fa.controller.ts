import { Body, Controller, Get, Post, Req, UseGuards } from "@nestjs/common";
import { ApiCookieAuth, ApiTags } from "@nestjs/swagger";
import qrcode from "qrcode";

import { JWTAuthGuard } from "~/common/guards/auth/jwt-auth.guard";

import { EnableTwoFADto } from "../dto/enable-2fa-dto";
import { TwoFAService } from "../services/2fa.service";

@ApiTags("Two Factor Auth")
@ApiCookieAuth()
@Controller("2fa")
@UseGuards(JWTAuthGuard)
export class TwoFAController {
  constructor(private twoFAService: TwoFAService) {}

  @Get("/generate")
  async generate(@Req() req: NestRequest) {
    const { otpAuthUrl, secret } = await this.twoFAService.generateTwoFASecret(
      req.user.id
    );

    return { qrcodeUrl: await qrcode.toDataURL(otpAuthUrl), secret };
  }

  @Post("/enable")
  async enable(@Req() req: NestRequest, @Body() dto: EnableTwoFADto) {
    await this.twoFAService.enableTwoFA(req.user.id, dto);

    return { message: "Two Factor authentication turned on" };
  }

  @Post("/disable")
  async disable(@Req() req: NestRequest) {
    return this.twoFAService.disableTwoFA(req.user.id);
  }
}
