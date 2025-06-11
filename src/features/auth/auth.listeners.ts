import { Inject, Injectable } from "@nestjs/common";
import { OnEvent } from "@nestjs/event-emitter";

import { appConfig } from "~/configs";
import { MailerService } from "~/core/mailer/mailer.service";

import { SendPasswordResetLinkEvent, UserRegisteredEvent } from "./auth.events";

export const USER_REGISTERED = "auth.registered";
export const RESEND_VERIFY_LINK = "auth.resendVerifyLink";
export const SEND_PASSWORD_RESET_LINK = "auth.sentPasswordResetLink";

@Injectable()
export class AuthEventListener {
  constructor(
    private mailService: MailerService,
    @Inject(appConfig.KEY) private appConfigs: Configs["app"]
  ) {}

  @OnEvent(USER_REGISTERED)
  async handleUserRegistered({ email, token }: UserRegisteredEvent) {
    const link = `${this.appConfigs.frontendUrl}/verify-email?token=${token}`;

    await this.mailService.sendmail({
      to: email,
      subject: "Confirm your Email",
      template: "verify-email",
      context: {
        appName: this.appConfigs.name,
        actionUrl: link,
      },
    });
  }

  @OnEvent(RESEND_VERIFY_LINK)
  async handleResendVerifyLink({ email, token }: UserRegisteredEvent) {
    const link = `${this.appConfigs.frontendUrl}/verify-email?token=${token}`;

    await this.mailService.sendmail({
      to: email,
      subject: "Reset your password",
      template: "reset-password",
      context: {
        appName: this.appConfigs.name,
        actionUrl: link,
      },
    });
  }

  @OnEvent(SEND_PASSWORD_RESET_LINK)
  async handleSendResetLink({ email, token }: SendPasswordResetLinkEvent) {
    const link = `${this.appConfigs.frontendUrl}/new-password?token=${token}`;

    await this.mailService.sendmail({
      to: email,
      subject: "Reset your password",
      template: "reset-password",
      context: {
        appName: this.appConfigs.name,
        actionUrl: link,
      },
    });
  }
}
