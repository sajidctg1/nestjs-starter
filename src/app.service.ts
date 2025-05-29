import { Injectable } from "@nestjs/common";

@Injectable()
export class AppService {
  constructor() {}

  async setup() {
    // await this.roleService.create({ name: "User", permissions: [] });
    // await this.roleService.create({ name: "Admin", permissions: [] });
  }

  getHello(): string {
    return "Hello World!";
  }
}
