import { CacheModule } from "@nestjs/cache-manager";
import { Module } from "@nestjs/common";
import { EventEmitterModule } from "@nestjs/event-emitter";

import { CoreModule } from "./core/core.module";
import { DatabaseModule } from "./database/database.module";
import { AuthModule } from "./features/auth/auth.module";

@Module({
  imports: [
    CacheModule.register({
      isGlobal: true,
      ttl: 5 * 1000, // 5 seconds
    }),
    EventEmitterModule.forRoot(),
    DatabaseModule,
    CoreModule,
    AuthModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
