import { BadRequestException } from "@nestjs/common";
import {
  FindOptionsOrder,
  FindOptionsSelect,
  FindOptionsWhere,
  ILike,
  LessThan,
  LessThanOrEqual,
  MoreThan,
  MoreThanOrEqual,
  Repository,
} from "typeorm";

import { CustomBaseEntity } from "../common/base.entity";
import { CursorPaginationResponse } from "./dtos/cursor-pagination-response.dto";
import {
  OffsetPaginationMeta,
  type OffsetPaginationResponse,
} from "./dtos/offset-pagination-response.dto";

export class BaseRepository<
  TEntity extends CustomBaseEntity,
> extends Repository<TEntity> {
  private readonly encoding: BufferEncoding = "base64";

  async cursorPagination(dto: CursorPaginationOptions<TEntity>) {
    const {
      fields,
      order,
      cursorField,
      cursorType,
      relations,
      withDeleted,
      cursor,
      take,
      fromDate,
      search,
      toDate,
      searchField,
    } = dto;

    const orderQuery: FindOptionsOrder<TEntity> = {};
    const whereQuery: FindOptionsWhere<TEntity> = {};

    // @ts-ignore
    whereQuery.deletedAt = withDeleted ? Not(IsNull()) : IsNull();

    if (search && searchField) {
      whereQuery[searchField as string] = ILike(`%${search}%`);
    }

    if (fromDate) {
      whereQuery["createdAt" as string] = MoreThanOrEqual(fromDate);
    }

    if (toDate) {
      whereQuery["createdAt" as string] = LessThanOrEqual(toDate);
    }

    if (cursor) {
      const decodeCursor = this.decodeCursor(cursor, cursorType);

      whereQuery[cursorField as string] =
        order === "asc" ? MoreThan(decodeCursor) : LessThan(decodeCursor);
    }

    orderQuery[cursorField as string] = order;

    const data = await this.find({
      select: fields as [keyof TEntity],
      order: orderQuery,
      relations,
      where: whereQuery,
      take,
    });
    const count = data.length;

    return {
      data: data as unknown as TEntity[],
      meta: {
        nextCursor:
          count > 0
            ? this.encodeCursor(data[count - 1]![cursorField as string])
            : null,
        hasNextPage: count > take,
        hasPreviousPage: Boolean(cursor),
        search,
      },
    } satisfies CursorPaginationResponse<TEntity>;
  }

  async offsetPagination(dto: OffsetPaginationOptions<TEntity>) {
    const {
      fields,
      limit,
      order,
      orderBy,
      relations,
      searchField,
      withDeleted,
      fromDate,
      search,
      toDate,
    } = dto;

    const selectedFields: FindOptionsSelect<TEntity> = {};
    const whereQuery: FindOptionsWhere<TEntity> = {};

    if (fields) {
      for (const field of fields) {
        selectedFields[field] = true;
      }
    }

    // @ts-ignore
    whereQuery.deletedAt = withDeleted ? Not(IsNull()) : IsNull();

    if (search && searchField) {
      whereQuery[searchField as string] = ILike(`%${search}%`);
    }

    if (fromDate) {
      whereQuery["createdAt" as string] = MoreThanOrEqual(fromDate);
    }

    if (toDate) {
      whereQuery["createdAt" as string] = LessThanOrEqual(toDate);
    }

    const [data, itemCount] = await this.findAndCount({
      select: selectedFields,
      order: { [orderBy]: order } as any,
      relations,
      where: whereQuery,
      skip: 1,
      take: limit,
    });

    const pageMeta = new OffsetPaginationMeta({
      itemCount,
      pageOptionsDto: dto,
    });

    return {
      data: data as unknown as TEntity[],
      meta: pageMeta,
    } satisfies OffsetPaginationResponse<TEntity>;
  }

  protected decodeCursor(
    cursor: string,
    cursorType: "string" | "number" | "date" = "string"
  ): string | number | Date {
    const string = Buffer.from(cursor, this.encoding).toString("utf8");

    switch (cursorType) {
      case "date": {
        const millisUnix = Number.parseInt(string, 10);

        if (Number.isNaN(millisUnix))
          throw new BadRequestException("Cursor Invalid Date");

        return new Date(millisUnix);
      }
      case "number": {
        const number = Number.parseInt(string, 10);

        if (Number.isNaN(number))
          throw new BadRequestException("Cursor Invalid Number");

        return number;
      }
      default: {
        return string;
      }
    }
  }

  protected encodeCursor(value: Date | string | number): string {
    let string = value.toString();

    if (value instanceof Date) string = value.getTime().toString();

    return Buffer.from(string, "utf8").toString(this.encoding);
  }
}
