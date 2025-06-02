import { Global, Module } from "@nestjs/common";
import { MailerModule as NestMailerModule } from "@nestjs-modules/mailer";
import { HandlebarsAdapter } from "@nestjs-modules/mailer/dist/adapters/handlebars.adapter";
import path from "node:path";

import { mailConfig, storageConfig } from "~/configs";

import { MailerService } from "./mailer.service";

@Global()
@Module({
  imports: [
    NestMailerModule.forRootAsync({
      inject: [mailConfig.KEY, storageConfig.KEY],
      useFactory: async (
        mailConf: Configs["mail"],
        fileConfigs: Configs["storage"]
      ) => ({
        transport: {
          host: mailConf.host,
          port: mailConf.port,
          ignoreTLS: true,
          secure: false,
          auth: {
            user: mailConf.username,
            pass: mailConf.password,
          },
        },
        defaults: {
          from: `"No Reply"<${mailConf.fromAddress}>`,
        },
        template: {
          dir: path.join(fileConfigs.basePath, "dist/resources/mail-templates"),
          adapter: new HandlebarsAdapter(),
          options: {
            strict: true,
          },
        },
        options: {
          partials: {
            dir: path.join(
              fileConfigs.basePath,
              "dist/resources/mail-templates/partials"
            ),
            options: { strict: true },
          },
        },
      }),
    }),
  ],
  providers: [MailerService],
  exports: [MailerService],
})
export class MailerModule {}
