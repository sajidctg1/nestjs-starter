import { Column, Entity } from "typeorm";

import { CustomBaseEntity } from "~/common/base.entity";

@Entity({ name: "role" })
export class RoleEntity extends CustomBaseEntity {
  @Column({ unique: true })
  name: string;

  @Column({ type: "jsonb" })
  permissions: any;

  constructor(items: Partial<RoleEntity>) {
    super();
    Object.assign(this, items);
  }
}
