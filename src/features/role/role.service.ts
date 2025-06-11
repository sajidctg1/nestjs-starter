import { Injectable } from "@nestjs/common";

import { ValidationException } from "~/common/exceptions/validation.exception";

import { CreateRoleDto } from "./dto/create-role.dto";
import { UpdateRoleDto } from "./dto/update-role.dto";
import { RoleEntity } from "./entities/role.entity";
import { RoleRepository } from "./repositories/role.repository";

@Injectable()
export class RoleService {
  constructor(private roleRepository: RoleRepository) {}

  async create(dto: CreateRoleDto) {
    if (await this.roleRepository.existsBy({ name: dto.name })) {
      throw new ValidationException("name", "already exists");
    }
    return this.roleRepository.save(new RoleEntity(dto));
  }

  async findAll() {
    return this.roleRepository.find();
  }

  async findDefault() {
    return this.roleRepository.findOneByOrFail({ name: "User" });
  }

  async findById(id: number) {
    return this.roleRepository.findOneByOrFail({ id });
  }

  async update(id: number, updateRoleDto: UpdateRoleDto) {
    return this.roleRepository.update({ id }, updateRoleDto);
  }

  async remove(id: number) {
    return this.roleRepository.delete({ id });
  }
}
