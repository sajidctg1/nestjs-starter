import { Injectable } from "@nestjs/common";
import { DataSource } from "typeorm";

import { BaseRepository } from "~/common/base.repository";

import { UserEntity } from "../entities/user.entity";

@Injectable()
export class UserRepository extends BaseRepository<UserEntity> {
  constructor(dataSource: DataSource) {
    super(UserEntity, dataSource.createEntityManager());
  }
}
