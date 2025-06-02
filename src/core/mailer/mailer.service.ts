import { Injectable, Logger } from "@nestjs/common";
import {
  type ISendMailOptions,
  MailerService as NestMailerService,
} from "@nestjs-modules/mailer";

@Injectable()
export class MailerService {
  private logger = new Logger(MailerService.name);

  constructor(private mailerService: NestMailerService) {}

  async sendmail(options: ISendMailOptions) {
    try {
      this.logger.debug(options.context);
      await this.mailerService.sendMail(options);
    } catch (error) {
      this.logger.error(error);
    }
  }
}
