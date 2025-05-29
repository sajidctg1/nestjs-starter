import { Injectable } from "@nestjs/common";
import { DataSource, Repository } from "typeorm";

import { RoleEntity } from "../entities/role.entity";

@Injectable()
export class RoleRepository extends Repository<RoleEntity> {
  constructor(dataSource: DataSource) {
    super(RoleEntity, dataSource.createEntityManager());
  }
}
