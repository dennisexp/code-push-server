'use strict';
var bcrypt = require('bcryptjs');
var crypto = require('crypto');
var fs = require('fs');
var qetag = require('../utils/qetag');
var _ = require('lodash');
var log4js = require('log4js');
var log = log4js.getLogger('cps:utils:security');
var AppError = require('../app-error');

var randToken = require('rand-token').generator({
    chars: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    source: 'crypto',
});

/**
 * added by dennise at 2021-12-16 for security.calcAllFilesBySha256
 */
const ignore_list = ['.codepushrelease', '.DS_Store', '__MACOSX'];
var security = {};
module.exports = security;

security.md5 = function (str) {
    var md5sum = crypto.createHash('md5');
    md5sum.update(str);
    str = md5sum.digest('hex');
    return str;
};

security.passwordHashSync = function (password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(12));
};

security.passwordVerifySync = function (password, hash) {
    return bcrypt.compareSync(password, hash);
};

security.randToken = function (num) {
    return randToken.generate(num);
};

security.parseToken = function (token) {
    return { identical: token.substr(-9, 9), token: token.substr(0, 28) };
};

security.fileSha256 = function (file) {
    return new Promise((resolve, reject) => {
        var rs = fs.createReadStream(file);
        var hash = crypto.createHash('sha256');
        rs.on('data', hash.update.bind(hash));
        rs.on('error', (e) => {
            reject(e);
        });
        rs.on('end', () => {
            resolve(hash.digest('hex'));
        });
    });
};

security.stringSha256Sync = function (contents) {
    var sha256 = crypto.createHash('sha256');
    sha256.update(contents);
    return sha256.digest('hex');
};


security.packageHashSync = function (jsonData) {
    var sortedArr = security.sortJsonToArr(jsonData);
    var manifestData = _.filter(sortedArr, (v) => {
        return !security.isPackageHashIgnored(v.path);
    }).map((v) => {
        return v.path + ':' + v.hash;
    });
    log.debug('packageHashSync manifestData:', manifestData);
    var manifestString = JSON.stringify(manifestData.sort());
     //将windows下的路径反斜杠转为斜杠---modified by dennise at 2022-1-12
    manifestString = _.replace(manifestString, /(\\|\/)+/g, '/');
    log.debug('packageHashSync manifestString:', manifestString);
    return security.stringSha256Sync(manifestString);
};

//参数为buffer或者readableStream或者文件路径
security.qetag = function (buffer) {
    if (typeof buffer === 'string') {
        try {
            log.debug(`Check upload file ${buffer} fs.R_OK`);
            fs.accessSync(buffer, fs.R_OK);
            log.debug(`Pass upload file ${buffer}`);
        } catch (e) {
            log.error(e);
            return Promise.reject(new AppError.AppError(e.message));
        }
    }
    log.debug(`generate file identical`);
    return new Promise((resolve, reject) => {
        qetag(buffer, (data) => {
            log.debug('identical:', data);
            resolve(data);
        });
    });
};

/**
 * out-of-date and to be deleted
 * script: 2021-12-16
 * @param {*} files 
 * @returns 
 */
security.sha256AllFiles = function (files) {
    return new Promise((resolve, reject) => {
        var results = {};
        var length = files.length;
        var count = 0;
        files.forEach((file) => {
            security.fileSha256(file).then((hash) => {
                results[file] = hash;
                count++;
                if (count == length) {
                    resolve(results);
                }
            });
        });
    });
};

security.uploadPackageType = function (directoryPath) {
    return new Promise((resolve, reject) => {
        var recursive = require('recursive-readdir');
        var path = require('path');
        var slash = require('slash');
        recursive(directoryPath, (err, files) => {
            if (err) {
                log.error(new AppError.AppError(err.message));
                reject(new AppError.AppError(err.message));
            } else {
                if (files.length == 0) {
                    log.debug(`uploadPackageType empty files`);
                    reject(new AppError.AppError('empty files'));
                } else {
                    var constName = require('../const');
                    const AREGEX = /android\.bundle/;
                    const AREGEX_IOS = /main\.jsbundle/;
                    var packageType = 0;
                    _.forIn(files, function (value) {
                        if (AREGEX.test(value)) {
                            packageType = constName.ANDROID;
                            return false;
                        }
                        if (AREGEX_IOS.test(value)) {
                            packageType = constName.IOS;
                            return false;
                        }
                    });
                    log.debug(`uploadPackageType packageType: ${packageType}`);
                    resolve(packageType);
                }
            }
        });
    });
};

// some files are ignored in calc hash in client sdk
// https://github.com/Microsoft/react-native-code-push/pull/974/files#diff-21b650f88429c071b217d46243875987R15
security.isHashIgnored = function (relativePath) {
    if (!relativePath) {
        return true;
    }

    const IgnoreMacOSX = '__MACOSX/';
    const IgnoreDSStore = '.DS_Store';

    return (
        relativePath.startsWith(IgnoreMacOSX) ||
        relativePath === IgnoreDSStore ||
        relativePath.endsWith(IgnoreDSStore)
    );
};

security.isPackageHashIgnored = function (relativePath) {
    if (!relativePath) {
        return true;
    }

    // .codepushrelease contains code sign JWT
    // it should be ignored in package hash but need to be included in package manifest
    const IgnoreCodePushMetadata = '.codepushrelease';
    return (
        relativePath === IgnoreCodePushMetadata ||
        relativePath.endsWith(IgnoreCodePushMetadata) ||
        security.isHashIgnored(relativePath)
    );
};

/**
 * added by dennise at 2021-12-16 replace security.calcAllFileSha256
 * key = relative path of each file
 * value = sha256(file)
 * @param {*} directory_path 
 * @param {*} prefix 
 * @param {*} manifest_entries 
 * @returns json
 */
security.calcAllFilesBySha256 = (directory_path, prefix='', manifest_entries={}) => {
    return new Promise(async(resolve, reject) => {
        let path = require('path');
        try {
            let file_list = fs.readdirSync(directory_path, {encoding: 'utf-8'});
            if (file_list==null || file_list.length==0) {
                return resolve({});
            }

            for (const file of file_list) {
                let relative_path = path.join(prefix, file);
                if (ignore_list.includes(file)) {
                    // console.log('ignored file:', relative_path);
                    log.debug(`ignored file:`, relative_path);
                    continue;
                }
                
                let absolute_path = path.join(directory_path, file);
                if (fs.statSync(absolute_path).isDirectory()) {
                    // console.log(absolute_path);
                    log.debug(absolute_path);
                    await security.calcAllFilesBySha256(absolute_path, relative_path, manifest_entries);
                }else{
                    let hash = await security.fileSha256(absolute_path);
                    manifest_entries[relative_path]=hash;
                }
            }

            resolve(manifest_entries);
        } catch (error) {
            // log.debug(`calcAllFilesBySha256 error:`, e);
            reject(error);
        }
    }).catch((e) => { 
        console.log(e);
        log.debug(`calcAllFilesBySha256 error:`, e);
        return {};
    });
}

/**
 * out-of-date and to be deleted
 * script: 2021-12-16
 * @param {*} directoryPath 
 * @returns 
 */
security.calcAllFileSha256 = function (directoryPath) {
    return new Promise((resolve, reject) => {
        var recursive = require('recursive-readdir');
        var path = require('path');
        var slash = require('slash');
        recursive(directoryPath, (error, files) => {
            if (error) {
                log.error(error);
                reject(new AppError.AppError(error.message));
            } else {
                // filter files that should be ignored
                files = files.filter((file) => {
                    var relative = path.relative(directoryPath, file);
                    return !security.isHashIgnored(relative);
                });

                if (files.length == 0) {
                    log.debug(`calcAllFileSha256 empty files in directoryPath:`, directoryPath);
                    reject(new AppError.AppError('empty files'));
                } else {
                    security.sha256AllFiles(files).then((results) => {
                        var data = {};
                        _.forIn(results, (value, key) => {
                            var relativePath = path.relative(directoryPath, key);
                            var matchresult = relativePath.match(/(\/|\\).*/);
                            if (matchresult) {
                                relativePath = path.join('CodePush', matchresult[0]);
                            }
                            relativePath = slash(relativePath);
                            data[relativePath] = value;
                        });
                        log.debug(`calcAllFileSha256 files:`, data);
                        resolve(data);
                    });
                }
            }
        });
    });
};

security.sortJsonToArr = function (json) {
    var rs = [];
    _.forIn(json, (value, key) => {
        rs.push({ path: key, hash: value });
    });
    return _.sortBy(rs, (o) => o.path);
};
