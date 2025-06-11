import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString } from "class-validator";

export class EnableTwoFADto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  code: string;
}
