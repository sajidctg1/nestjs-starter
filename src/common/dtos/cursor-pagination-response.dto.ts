import { ApiProperty } from "@nestjs/swagger";
import { IsArray } from "class-validator";

export class CursorMeta {
  @ApiProperty()
  nextCursor!: string | null;

  @ApiProperty()
  hasNextPage!: boolean;

  @ApiProperty()
  hasPreviousPage!: boolean;

  @ApiProperty()
  search?: string;
}

export class CursorPaginationResponse<T> {
  @IsArray()
  @ApiProperty({ isArray: true })
  readonly data!: T[];

  @ApiProperty({ type: () => CursorMeta })
  readonly meta!: CursorMeta;
}
