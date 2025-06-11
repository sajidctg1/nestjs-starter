import { DataSource, type DataSourceOptions } from "typeorm";

import { dbConfig } from "~/configs";
import { env } from "~/configs/env";

import "reflect-metadata";

const cnf = dbConfig();

export const AppDataSource = new DataSource({
  type: cnf.sql.type,
  url: cnf.url,
  host: cnf.sql.host,
  port: cnf.sql.port,
  username: cnf.sql.username,
  password: cnf.sql.password,
  database: cnf.sql.dbName,
  synchronize: cnf.sql.synchronize,
  dropSchema: false,
  keepConnectionAlive: true,
  logging: env.NODE_ENV !== "production",
  entities: [__dirname + "/../**/*.entity{.ts,.js}"],
  migrations: [__dirname + "/migrations/**/*{.ts,.js}"],
  cli: {
    entitiesDir: "src",
    subscribersDir: "subscriber",
  },
  extra: {
    max: cnf.sql.maxConnections,
  },
} as DataSourceOptions);
