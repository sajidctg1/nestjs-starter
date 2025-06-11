import {
  Column,
  Entity,
  Index,
  OneToOne,
  PrimaryGeneratedColumn,
} from "typeorm";

import { UserEntity } from "./user.entity";

@Entity({ name: "account" })
export class AccountEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  @Index()
  userId: number;

  @OneToOne(() => UserEntity)
  user: UserEntity;

  @Column()
  provider: string;

  @Column()
  providerAccountId: string;

  constructor(items: Partial<AccountEntity>) {
    Object.assign(this, items);
  }
}
