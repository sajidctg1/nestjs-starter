import { Injectable, NotFoundException } from "@nestjs/common";
import { EntityNotFoundError } from "typeorm";

import { ValidationException } from "~/common/exceptions/validation.exception";

import { RoleEntity } from "../role/entities/role.entity";
import { RoleService } from "../role/role.service";
import { CreateOauthAccountDto } from "./dto/create-account.dto";
import { CreateUserDto } from "./dto/create-user.dto";
import { UpdateUserDto } from "./dto/update-user.dto";
import { AccountEntity } from "./entities/account.entity";
import { UserEntity } from "./entities/user.entity";
import { AccountRepository } from "./repositories/account.repository";
import { UserRepository } from "./repositories/user.repository";

@Injectable()
export class UserService {
  constructor(
    private roleService: RoleService,
    private userRepository: UserRepository,
    private accountRepository: AccountRepository
  ) {}

  async create(dto: CreateUserDto) {
    if (await this.userRepository.existsBy({ email: dto.email })) {
      throw new ValidationException("email", "already exists");
    }

    if (await this.userRepository.existsBy({ username: dto.username })) {
      throw new ValidationException("username", "already exists");
    }

    let role: RoleEntity;
    try {
      if (dto.roleId) {
        role = await this.roleService.findById(dto.roleId);
      } else {
        role = await this.roleService.findDefault();
      }
    } catch (error) {
      if (!(error instanceof EntityNotFoundError)) throw error;

      if (dto.roleId) {
        throw new ValidationException("role", `Role '${dto.roleId}' not found`);
      }

      throw new Error(`Role "User" not found in db.`);
    }

    const user = new UserEntity({ ...dto, roleId: role.id });
    user.hashPassword();

    return this.userRepository.save(user);
  }

  async findAll() {
    return await this.userRepository.find();
  }

  async findById(id: number) {
    const data = await this.userRepository.findOneBy({ id });
    if (!data) throw new NotFoundException();
    return data;
  }

  async findByEmail(email: string) {
    const data = await this.userRepository.findOneBy({ email });
    if (!data) throw new NotFoundException();
    return data;
  }

  async update(id: number, updateUserDto: UpdateUserDto) {
    return await this.userRepository.update({ id }, updateUserDto);
  }

  async remove(id: number) {
    return await this.userRepository.delete({ id });
  }

  async createOauthAccount({ user, account }: CreateOauthAccountDto) {
    const newUser = await this.userRepository.save(new UserEntity(user));
    const newAccoount = await this.accountRepository.save(
      new AccountEntity({
        userId: newUser.id,
        ...account,
      })
    );

    return { user: newUser, account: newAccoount };
  }
}
