import {
  BadRequestException,
  Inject,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { authenticator } from "otplib";

import { appConfig } from "~/configs";
import { UserService } from "~/features/user/user.service";

import { EnableTwoFADto } from "../dto/enable-2fa-dto";

@Injectable()
export class TwoFAService {
  constructor(
    @Inject(appConfig.KEY) private appConfig: Configs["app"],
    private userService: UserService
  ) {}

  async enableTwoFA(userId: number, dto: EnableTwoFADto) {
    const isValid = await this.isValidTwoFACode({ userId, code: dto.code });
    if (!isValid) {
      throw new UnauthorizedException("Invalid authentication code");
    }

    return this.userService.update(userId, { isTwoFAEnabled: true });
  }

  async disableTwoFA(userId: number) {
    return this.userService.update(userId, { isTwoFAEnabled: false });
  }

  async generateTwoFASecret(userId: number) {
    const user = await this.userService.findById(userId);
    const secret = authenticator.generateSecret();
    const otpAuthUrl = authenticator.keyuri(
      user.email,
      this.appConfig.name,
      secret
    );

    await this.userService.update(user.id, { twoFASecret: secret });

    return { secret, otpAuthUrl };
  }

  async isValidTwoFACode({ userId, code }: { userId: number; code: string }) {
    const user = await this.userService.findById(userId);
    const secret = user.twoFASecret;
    if (!secret) throw new BadRequestException("Two Factor Aauth is disabled");

    return authenticator.verify({ token: code, secret });
  }
}
