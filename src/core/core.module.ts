import { ClassSerializerInterceptor, Module } from "@nestjs/common";
import { APP_FILTER, APP_INTERCEPTOR } from "@nestjs/core";

import { ConfigModule } from "./config/config.module";
import { EntityNotfoundExceptionFilter } from "./filters/entity-notfound-exception.filter";
import { LoggingInterceptor } from "./interceptors/logging/logging.interceptor";
import { MailerModule } from "./mailer/mailer.module";

@Module({
  imports: [ConfigModule, MailerModule],
  providers: [
    {
      provide: APP_FILTER,
      useClass: EntityNotfoundExceptionFilter,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: ClassSerializerInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggingInterceptor,
    },
  ],
})
export class CoreModule {}
