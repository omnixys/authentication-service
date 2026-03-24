/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * For more information, visit <https://www.gnu.org/licenses/>.
 */

/**
 * BannerService - Service zur Anzeige von Anwendungsinformationen und einem Startbanner.
 * BannerService
 * Dieser Service gibt beim Start der Anwendung ein Banner und wichtige Anwendungsinformationen aus.
 */

import { env } from './config/env.js';
import { nodeConfig } from './config/node.js';
import { Injectable, type OnApplicationBootstrap } from '@nestjs/common';
import { getLogger } from '@omnixys/logger';
import cFonts from 'cfonts';
import chalk from 'chalk';
import { release, type, userInfo } from 'node:os';
import process from 'node:process';

/**
 * BannerService - Service zum Generieren und Ausgeben von Anwendungsinformationen sowie einem Banner.
 * Dieser Service wird beim Bootstrap der Anwendung verwendet, um sowohl ein benutzerdefiniertes Banner
 * als auch wichtige Systeminformationen auszugeben.
 */
@Injectable()
export class BannerService implements OnApplicationBootstrap {
  readonly #logger = getLogger(BannerService.name);

  /**
   * @description Wird beim Bootstrap der Anwendung ausgeführt, um Anwendungsinformationen und ein Banner auszugeben.
   */
  onApplicationBootstrap(): void {
    const {
      host,
      nodeEnv,
      port,
      tempo,
      protocoll,
      keysPath,
      keycloak,
      logger,
      serviceName,
      kafkaUri,
    } = nodeConfig;

    const { KEYCLOAK_HEALTH_URL, TEMPO_HEALTH_URL, PROMETHEUS_HEALTH_URL } = env;

    // Banner generieren und ausgeben
    this.#generateBanner(serviceName);

    // Umgebungsinformationen mit Farben ausgeben
    this.#logger.info(chalk.green('=== Anwendungsinformationen ==='));
    this.#logger.info(chalk.cyan('Anwendungsname: ') + chalk.yellow(serviceName));
    this.#logger.info(chalk.cyan('Node.js-Version: ') + chalk.yellow(process.version));
    this.#logger.info(chalk.cyan('Umgebung: ') + chalk.yellow(nodeEnv));
    this.#logger.info(chalk.cyan('Host: ') + chalk.yellow(host));
    this.#logger.info(chalk.cyan('Port: ') + chalk.yellow(port.toString()));
    this.#logger.info(chalk.cyan('Betriebssystem: ') + chalk.yellow(`${type()} (${release()})`));
    this.#logger.info(chalk.cyan('Benutzer: ') + chalk.yellow(userInfo().username));
    this.#logger.info(chalk.cyan('HTTPS: ') + chalk.yellow(protocoll));
    this.#logger.info(chalk.cyan('Keys path: ') + chalk.yellow(keysPath));
    this.#logger.info(chalk.green('===============LOGGER============'));
    if (logger.logDefault) {
      this.#logger.info(chalk.cyan('Default Logger!'));
    } else {
      this.#logger.info(chalk.cyan('Log Directory ') + chalk.yellow(logger.logDir));
      this.#logger.info(chalk.cyan('Log Filename: ') + chalk.yellow(logger.logFileName));
      this.#logger.info(chalk.cyan('Pretty Logging: ') + chalk.yellow(logger.logPretty));
      this.#logger.info(chalk.cyan('Custom Log Level: ') + chalk.yellow(logger.logLevel));
    }
    this.#logger.info(chalk.green('==============KEYCLOAK==========='));
    this.#logger.info(chalk.cyan('URI: ') + chalk.yellow(keycloak.url));
    this.#logger.info(chalk.cyan('Realm: ') + chalk.yellow(keycloak.realm));
    this.#logger.info(chalk.cyan('client: ') + chalk.yellow(keycloak.clientId));
    this.#logger.info(chalk.cyan('Keys path: ') + chalk.yellow(keysPath));
    this.#logger.info(chalk.green('==============HEALTH==========='));
    this.#logger.info(chalk.cyan('Kycloak Health URI: ') + chalk.yellow(KEYCLOAK_HEALTH_URL));
    this.#logger.info(chalk.cyan('Tempo Health URI: ') + chalk.yellow(TEMPO_HEALTH_URL));
    this.#logger.info(chalk.cyan('Prometheus Health URI: ') + chalk.yellow(PROMETHEUS_HEALTH_URL));
    this.#logger.info(chalk.green('==============KAFKA==========='));
    this.#logger.info(chalk.cyan('Kafka Broker URI: ') + chalk.yellow(kafkaUri));
    this.#logger.info(chalk.green('==============OBSERVABILITY==========='));
    this.#logger.info(chalk.cyan('Tempo URI: ') + chalk.yellow(tempo));
    this.#logger.info(chalk.green('===============================')); // Endmarkierung für die Anwendungsinformationen
  }

  /**
   * @description Banner generieren und ausgeben.
   */
  #generateBanner(serviceName: string): void {
    cFonts.say(serviceName, {
      font: 'block', // Schriftart des Banners
      align: 'left', // Ausrichtung des Textes
      gradient: ['white', 'black'], // Farbverlauf für das Banner
      background: 'transparent', // Hintergrund des Banners
      letterSpacing: 1, // Buchstabenabstand
      lineHeight: 1, // Zeilenhöhe
    });
  }
}
