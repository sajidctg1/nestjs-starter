import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";

import { RoleModule } from "../role/role.module";
import { UserController } from "./controllers/user.controller";
import { AccountRepository } from "./repositories/account.repository";
import { UserRepository } from "./repositories/user.repository";
import { UserService } from "./user.service";

@Module({
  imports: [
    TypeOrmModule.forFeature([UserRepository, AccountRepository]),
    RoleModule,
  ],
  controllers: [UserController],
  providers: [UserService, UserRepository, AccountRepository],
  exports: [UserService],
})
export class UserModule {}
