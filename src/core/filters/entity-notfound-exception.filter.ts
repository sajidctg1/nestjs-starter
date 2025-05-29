import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  NotFoundException,
} from "@nestjs/common";
import { EntityNotFoundError } from "typeorm";

@Catch(EntityNotFoundError)
export class EntityNotfoundExceptionFilter implements ExceptionFilter {
  catch(_exception: unknown, _host: ArgumentsHost) {
    const response = _host.switchToHttp().getResponse<NestResponse>();

    response.status(404).send(new NotFoundException().getResponse());
  }
}
