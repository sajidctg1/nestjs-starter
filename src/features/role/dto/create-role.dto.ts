import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsObject, IsString } from "class-validator";

export class CreateRoleDto {
  @ApiProperty({ example: "User" })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: {} })
  @IsObject()
  @IsNotEmpty()
  permissions: Record<string, any>;
}
