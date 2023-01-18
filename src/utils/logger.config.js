import log4js from 'log4js';
import { config } from './config.js';

log4js.configure({
    appenders: {
        console: {type: 'console'},
        debugFile: { type: 'file', filename: './debug.log'},
        errorFile: { type: 'file', filename: './error.log'},
        //
        loggerConsole: { type: 'logLevelFilter', appender: 'console', level: 'info'},
        loggerDebug: { type: 'logLevelFilter', appender: 'debugFile', level: 'info'},
        loggerError: { type: 'logLevelFilter', appender: 'errorFile', level: 'warn'},
    },
    categories: {
        default: {
            appenders: ['loggerConsole', 'loggerDebug'],
            level: 'all'
        },
        production: {
            appenders: ['loggerError'],
            level: 'all'
        }
    }
});

let logger = null;

if (config.env == 'production') {
    logger = log4js.getLogger('production')
} else {
    logger = log4js.getLogger()
}

export {logger}