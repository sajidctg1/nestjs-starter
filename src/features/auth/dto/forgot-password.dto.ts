import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty } from "class-validator";

export class ForgetPasswordDto {
  @ApiProperty({ example: "jhon@example.com" })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
