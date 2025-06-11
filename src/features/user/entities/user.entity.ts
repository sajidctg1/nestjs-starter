import bcrypt from "bcryptjs";
import { Exclude } from "class-transformer";
import { Column, Entity, Index, OneToOne } from "typeorm";

import { CustomBaseEntity } from "~/common/base.entity";
import { RoleEntity } from "~/features/role/entities/role.entity";

const BCRYPT_SALT = 10;

@Entity({ name: "user" })
export class UserEntity extends CustomBaseEntity {
  @Column()
  firstName: string;

  @Column({ nullable: true })
  lastName?: string;

  @Column()
  @Index({ unique: true })
  username: string;

  @Column()
  @Index({ unique: true })
  email: string;

  @Exclude({ toPlainOnly: true })
  @Column({ nullable: true })
  password?: string;

  @Column({ nullable: true })
  avatar?: string;

  @Exclude({ toPlainOnly: true })
  @Column({ default: false })
  isVerified: boolean;

  @Column({ default: false })
  isTwoFAEnabled: boolean;

  @Exclude({ toPlainOnly: true })
  @Column({ nullable: true })
  twoFASecret?: string;

  @Column()
  roleId: number;

  @OneToOne(() => RoleEntity)
  role: RoleEntity;

  constructor(items: Partial<UserEntity>) {
    super();
    Object.assign(this, items);
  }

  hashPassword() {
    if (!this.password) return;

    this.password = bcrypt.hashSync(this.password, BCRYPT_SALT);
  }
}
