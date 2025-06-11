import {
  type INestApplication,
  type ValidationPipeOptions,
} from "@nestjs/common";
import { Logger, UnprocessableEntityException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { ValidationError } from "class-validator";

const logger = new Logger("App:Utils");

function classValidatorErrFormat(err: ValidationError) {
  if (err.children && err.children.length > 0) {
    return {
      field: err.property,
      error: err.constraints?.nestedValidation
        ? err.constraints.nestedValidation
        : err.children.map((i) => classValidatorErrFormat(i)),
      // : err.children.map(({property, ...rest}) => classValidatorErrFormat({...rest, property: `${err.property}.${property}`}))
    };
  } else {
    return {
      field: err.property,
      // parent: err.property.split(".").length > 1 ? err.property.split(".")[0] : null,
      error: Object.values(err.constraints ?? {}),
    };
  }
}

/**
 * The `CaseInsensitiveFilterPlugin` function returns an object with a `fn` property that contains an
 * `opsFilter` method, which filters an array of tagged operations based on a case-insensitive phrase.
 * @returns An object with a `fn` property that contains an `opsFilter` method.
 */
function CaseInsensitiveFilterPlugin() {
  return {
    fn: {
      opsFilter: (
        taggedOps: {
          filter: (
            argument: (_tagObject: unknown, tag: string) => boolean
          ) => any;
        },
        phrase: string
      ) => {
        return taggedOps.filter((_tagObject: unknown, tag: string): boolean =>
          tag.toLowerCase().includes(phrase.toLowerCase())
        ) as unknown as {
          filter: (
            argument: (_tagObject: unknown, tag: string) => boolean
          ) => any;
        };
      },
    },
  };
}

async function gracefulShutdown(app: INestApplication, code: string) {
  setTimeout(() => process.exit(1), 5000);
  logger.verbose(`Signal received with code ${code} ⚡.`);
  logger.log("❗Closing http server with grace.");

  try {
    await app.close();
    logger.log("✅ Http server closed.");
    process.exit(0);
  } catch (error: any) {
    logger.error(`❌ Http server closed with error: ${error}`);
    process.exit(1);
  }
}

export const AppUtils = {
  validationPipeOptions(): ValidationPipeOptions {
    return {
      exceptionFactory: (errors: ValidationError[] = []) => {
        return new UnprocessableEntityException({
          message: "Validation failed!",
          fields: errors.map(classValidatorErrFormat),
        });
      },
      whitelist: true,
      transform: true,
      forbidUnknownValues: false,
      validateCustomDecorators: true,
    };
  },

  killAppWithGrace(app: INestApplication) {
    process.on("SIGINT", () => {
      gracefulShutdown(app, "SIGINT");
    });

    process.on("SIGTERM", () => {
      gracefulShutdown(app, "SIGTERM");
    });
  },

  setupSwagger(
    app: INestApplication,
    configService: ConfigService<Configs, true>
  ) {
    const appName = configService.get("app.name", { infer: true });

    const options = new DocumentBuilder()
      .setTitle(`${appName} API Documentation`)
      .addBearerAuth()
      .setLicense("MIT", "https://opensource.org/licenses/MIT")
      .setDescription("Nestjs Typeorm starter kit")
      .setVersion("1.0.0")
      .addBearerAuth(
        { type: "http", scheme: "bearer", bearerFormat: "JWT" },
        "accessToken"
      )
      .addBearerAuth(
        { type: "http", scheme: "bearer", bearerFormat: "JWT" },
        "refreshToken"
      )
      .addApiKey({ type: "apiKey", in: "header", name: "x-api-key" }, "apiKey")
      .build();

    const document = SwaggerModule.createDocument(app, options, {});

    // const paths = Object.values((document).paths);

    // for (const path of paths) {
    //   const methods = Object.values(path) as { security: string[] }[];

    //   for (const method of methods) {
    //     if (method.security instanceof Array && method.security.includes(IS_PUBLIC_KEY_META)
    //     )
    //       method.security = [];
    //   }
    // }

    // app.use(
    //   getMiddleware({
    //     swaggerSpec: document,
    //     authentication: true,
    //     hostname: appName,
    //     uriPath: "/stats",
    //     onAuthenticate: (_request: any, username: string, password: string) => {
    //       return username === userName && password === passWord;
    //     },
    //   }),
    // );

    SwaggerModule.setup("doc", app, document, {
      explorer: true,
      swaggerOptions: {
        docExpansion: "list",
        filter: true,
        showRequestDuration: true,
        tryItOutEnabled: true,
        displayOperationId: true,
        persistAuthorization: true,
        plugins: [CaseInsensitiveFilterPlugin],
        operationsSorter: (
          a: { get: (argument: string) => string },
          b: { get: (argument: string) => string }
        ) => {
          const methodsOrder = [
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "options",
            "trace",
          ];
          let result =
            methodsOrder.indexOf(a.get("method")) -
            methodsOrder.indexOf(b.get("method"));

          if (result === 0) result = a.get("path").localeCompare(b.get("path"));

          return result;
        },
      },
    });
  },
};
