/*
 * Minio Javascript Library for Amazon S3 Compatible Cloud Storage, (C) 2015 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

var os = require('os');
var stream = require('stream');
var crypto = require('crypto');
var async = require('async');
var _ = require('lodash');
var fs = require('fs');
var http = require('http');
var https = require('https');
var url = require('url');
var chai = require('chai');
var assert = chai.assert;
var superagent = require('superagent');
var uuid = require("uuid");
var minio = undefined;

try {
  minio = require('../../../dist/main/minio');
} catch (err) {
  minio = require('minio');
}

var Policy = minio.Policy;

require('source-map-support').install();

describe('functional tests', function () {
  this.timeout(30 * 60 * 1000);
  var playConfig = {};
  // If credentials aren't given, default to play.minio.io.
  if (process.env['SERVER_ENDPOINT']) {
    var res = process.env['SERVER_ENDPOINT'].split(":");
    playConfig.endPoint = res[0];
    playConfig.port = parseInt(res[1]);
  } else {
    playConfig.endPoint = 'play.minio.io';
    playConfig.port = 9000;
  }
  playConfig.accessKey = process.env['ACCESS_KEY'] || 'Q3AM3UQ867SPQQA43P2F';
  playConfig.secretKey = process.env['SECRET_KEY'] || 'zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG';

  // If the user provides ENABLE_HTTPS, 1 = secure, anything else = unsecure.
  // Otherwise default to secure.
  if (process.env['ENABLE_HTTPS'] !== undefined) {
    playConfig.secure = process.env['ENABLE_HTTPS'] == '1';
  } else {
    playConfig.secure = true;
  }

  // dataDir is falsy if we need to generate data on the fly. Otherwise, it will be
  // a directory with files to read from, i.e. /mint/data.
  var dataDir = process.env['MINT_DATA_DIR'];

  var client = new minio.Client(playConfig);
  var usEastConfig = playConfig;
  usEastConfig.region = 'us-east-1';
  var clientUsEastRegion = new minio.Client(usEastConfig);

  var bucketName = uuid.v4();
  var objectName = uuid.v4();

  var _1byteObjectName = 'datafile-1-b';
  var _1byte = dataDir ? fs.readFileSync(dataDir + '/' + _1byteObjectName) : new Buffer(1).fill(0);

  var _100kbObjectName = 'datafile-100-kB';
  var _100kb = dataDir ? fs.readFileSync(dataDir + '/' + _100kbObjectName) : new Buffer(100 * 1024).fill(0);
  var _100kbObjectNameCopy = _100kbObjectName + '_copy';

  var _100kbObjectBufferName = _100kbObjectName + '.buffer';
  var _100kbObjectStringName = _100kbObjectName + '.string';
  var _100kbmd5 = crypto.createHash('md5').update(_100kb).digest('hex');

  var _6mbObjectName = 'datafile-6-MB';
  var _6mb = dataDir ? fs.readFileSync(dataDir + '/' + _6mbObjectName) : new Buffer(6 * 1024 * 1024).fill(0);
  var _6mbmd5 = crypto.createHash('md5').update(_6mb).digest('hex');
  var _6mbObjectNameCopy = _6mbObjectName + '_copy';

  var _5mbObjectName = 'datafile-5-MB';
  var _5mb = dataDir ? fs.readFileSync(dataDir + '/' + _5mbObjectName) : new Buffer(5 * 1024 * 1024).fill(0);
  var _5mbmd5 = crypto.createHash('md5').update(_5mb).digest('hex');

  var tmpDir = os.tmpdir();

  var traceStream;

  // FUNCTIONAL_TEST_TRACE env variable contains the path to which trace
  // will be logged. Set it to /dev/stdout log to the stdout.
  if (process.env['FUNCTIONAL_TEST_TRACE']) {
    var filePath = process.env['FUNCTIONAL_TEST_TRACE'];
    // This is necessary for windows.
    if (filePath === 'process.stdout') {
      traceStream = process.stdout;
    } else {
      traceStream = fs.createWriteStream(filePath, { flags: 'a' });
    }
    traceStream.write('====================================\n');
    client.traceOn(traceStream);
  }

  before(function (done) {
    return client.makeBucket(bucketName, '', done);
  });
  after(function (done) {
    return client.removeBucket(bucketName, done);
  });

  if (traceStream) {
    after(function () {
      client.traceOff();
      if (filePath !== 'process.stdout') {
        traceStream.end();
      }
    });
  }

  describe('makeBucket with period and region', function () {
    if (playConfig.endPoint === 's3.amazonaws.com') {
      it('should create bucket in eu-central-1 with period', function (done) {
        return client.makeBucket(bucketName + '.sec.period', 'eu-central-1', done);
      });
      it('should delete bucket', function (done) {
        return client.removeBucket(bucketName + '.sec.period', done);
      });
    }
  });

  describe('listBuckets', function () {
    it('should list bucket', function (done) {
      client.listBuckets(function (e, buckets) {
        if (e) return done(e);
        if (_.find(buckets, { name: bucketName })) return done();
        done(new Error('bucket not found'));
      });
    });
    it('should list buckets as promise', function (done) {
      client.listBuckets().then(function (buckets) {
        if (!_.find(buckets, { name: bucketName })) throw new Error('bucket not found');
      }).then(function () {
        return done();
      })['catch'](done);
    });
  });

  describe('makeBucket with region', function () {
    it('should fail', function (done) {
      try {
        clientUsEastRegion.makeBucket(bucketName + '.region', 'us-east-2', assert.fail);
      } catch (e) {
        done();
      }
    });
    it('should succeed', function (done) {
      clientUsEastRegion.makeBucket(bucketName + '.region', 'us-east-1', done);
    });
    it('should delete bucket', function (done) {
      clientUsEastRegion.removeBucket(bucketName + '.region', done);
    });
    it('should succeed as promise', function (done) {
      clientUsEastRegion.makeBucket(bucketName + '.region', 'us-east-1').then(function () {
        return done();
      })['catch'](done);
    });
    it('should delete bucket', function (done) {
      clientUsEastRegion.removeBucket(bucketName + '.region').then(function () {
        return done();
      })['catch'](done);
    });
  });

  describe('bucketExists', function () {
    it('should check if bucket exists', function (done) {
      return client.bucketExists(bucketName, done);
    });
    it('should check if bucket does not exist', function (done) {
      client.bucketExists(bucketName + 'random', function (e) {
        if (e.code === 'NoSuchBucket') return done();
        done(new Error());
      });
    });
    it('should check if bucket exists, promise', function (done) {
      client.bucketExists(bucketName).then(function () {
        return done();
      })['catch'](done);
    });
  });

  describe('removeBucket', function () {
    it('should fail for nonexistent bucket', function (done) {
      client.removeBucket("nonexistentbucket", function (e) {
        if (e.code === 'NoSuchBucket') return done();
        done(new Error());
      });
    });
    it('should succeed as promise', function (done) {
      client.makeBucket(bucketName + '.region', 'us-east-1').then(client.removeBucket(bucketName + '.region')).then(function () {
        return done();
      })['catch'](done);
    });
  });
  describe('tests for putObject copyObject getObject getPartialObject statObject removeObject', function () {
    it('should upload 100KB stream', function (done) {
      var stream = readableStream(_100kb);
      client.putObject(bucketName, _100kbObjectName, stream, _100kb.length, '', done);
    });

    it('should download 100KB and match content', function (done) {
      var hash = crypto.createHash('md5');
      client.getObject(bucketName, _100kbObjectName, function (e, stream) {
        if (e) return done(e);
        stream.on('data', function (data) {
          return hash.update(data);
        });
        stream.on('error', done);
        stream.on('end', function () {
          if (hash.digest('hex') === _100kbmd5) return done();
          done(new Error('content mismatch'));
        });
      });
    });

    it('should upload 100KB Buffer', function (done) {
      client.putObject(bucketName, _100kbObjectBufferName, _100kb, '', done);
    });

    it('should download 100KB Buffer upload and match content', function (done) {
      var hash = crypto.createHash('md5');
      client.getObject(bucketName, _100kbObjectBufferName, function (e, stream) {
        if (e) return done(e);
        stream.on('data', function (data) {
          return hash.update(data);
        });
        stream.on('error', done);
        stream.on('end', function () {
          if (hash.digest('hex') === _100kbmd5) return done();
          done(new Error('content mismatch'));
        });
      });
    });

    it('should upload 100KB string', function (done) {
      client.putObject(bucketName, _100kbObjectStringName, _100kb.toString(), '', done);
    });

    it('should download 100KB string upload and match content', function (done) {
      var hash = crypto.createHash('md5');
      client.getObject(bucketName, _100kbObjectStringName, function (e, stream) {
        if (e) return done(e);
        stream.on('data', function (data) {
          return hash.update(data);
        });
        stream.on('error', done);
        stream.on('end', function () {
          if (hash.digest('hex') === _100kbmd5) return done();
          done(new Error('content mismatch'));
        });
      });
    });

    it('should upload 100KB Buffer, as promise', function (done) {
      client.putObject(bucketName, _100kbObjectBufferName, _100kb, '').then(function () {
        return done();
      })['catch'](done);
    });

    it('should download partial data (1KB of 100KB), as promise', function (done) {
      client.getPartialObject(bucketName, _100kbObjectBufferName, 0, 1024).then(function (stream) {
        stream.on('data', function () {});
        stream.on('end', done);
      })['catch'](done);
    });

    it('should download 100KB Buffer, as promise', function (done) {
      client.getObject(bucketName, _100kbObjectBufferName).then(function (stream) {
        stream.on('data', function () {});
        stream.on('end', done);
      })['catch'](done);
    });

    it('should upload 6mb', function (done) {
      var stream = readableStream(_6mb);
      client.putObject(bucketName, _6mbObjectName, stream, _6mb.length, '', done);
    });

    it('should download 6mb and match content', function (done) {
      var hash = crypto.createHash('md5');
      client.getObject(bucketName, _6mbObjectName, function (e, stream) {
        if (e) return done(e);
        stream.on('data', function (data) {
          return hash.update(data);
        });
        stream.on('error', done);
        stream.on('end', function () {
          if (hash.digest('hex') === _6mbmd5) return done();
          done(new Error('content mismatch'));
        });
      });
    });

    it('should download partial data (100kb of the 6mb file) and match content', function (done) {
      var hash = crypto.createHash('md5');
      client.getPartialObject(bucketName, _6mbObjectName, 0, 100 * 1024, function (e, stream) {
        if (e) return done(e);
        stream.on('data', function (data) {
          return hash.update(data);
        });
        stream.on('error', done);
        stream.on('end', function () {
          if (hash.digest('hex') === _100kbmd5) return done();
          done(new Error('content mismatch'));
        });
      });
    });

    it('should copy object', function (done) {
      client.copyObject(bucketName, _6mbObjectNameCopy, "/" + bucketName + "/" + _6mbObjectName, function (e) {
        if (e) return done(e);
        done();
      });
    });

    it('should copy object, as promise', function (done) {
      client.copyObject(bucketName, _6mbObjectNameCopy, "/" + bucketName + "/" + _6mbObjectName).then(function () {
        return done();
      })['catch'](done);
    });

    it('should stat object', function (done) {
      client.statObject(bucketName, _6mbObjectName, function (e, stat) {
        if (e) return done(e);
        if (stat.size !== _6mb.length) return done(new Error('size mismatch'));
        done();
      });
    });

    it('should stat object, as promise', function (done) {
      client.statObject(bucketName, _6mbObjectName).then(function (stat) {
        if (stat.size !== _6mb.length) throw new Error('size mismatch');
      }).then(function () {
        return done();
      })['catch'](done);
    });

    it('should remove objects created for test', function (done) {
      client.removeObject(bucketName, _100kbObjectName).then(function () {
        async.map([_100kbObjectBufferName, _100kbObjectStringName, _6mbObjectName, _6mbObjectNameCopy], function (objectName, cb) {
          return client.removeObject(bucketName, objectName, cb);
        }, done);
      })['catch'](done);
    });
  });

  describe('tests for copyObject statObject', function () {
    it('should upload 100KB Buffer with custom content type', function (done) {
      client.putObject(bucketName, _100kbObjectName, _100kb, 'custom/content-type', done);
    });

    it('should copy object with no conditions specified', function (done) {
      client.copyObject(bucketName, _100kbObjectNameCopy, "/" + bucketName + "/" + _100kbObjectName, function (e) {
        if (e) return done(e);
        done();
      });
    });

    it('should stat copied object', function (done) {
      client.statObject(bucketName, _100kbObjectNameCopy, function (e, stat) {
        if (e) return done(e);
        if (stat.size !== _100kb.length) return done(new Error('size mismatch'));
        if (stat.contentType !== 'custom/content-type') return done(new Error('content-type mismatch'));
        done();
      });
    });
    it('should copy object with conditions specified', function (done) {
      var conds = new minio.CopyConditions();
      conds.setMatchETagExcept('bd891862ea3e22c93ed53a098218791d');
      client.copyObject(bucketName, _100kbObjectNameCopy, "/" + bucketName + "/" + _100kbObjectName, conds, function (e) {
        if (e) return done(e);
        done();
      });
    });

    it('should stat copied object', function (done) {
      client.statObject(bucketName, _100kbObjectNameCopy, function (e, stat) {
        if (e) return done(e);
        if (stat.size !== _100kb.length) return done(new Error('size mismatch'));
        if (stat.contentType !== 'custom/content-type') return done(new Error('content-type mismatch'));
        done();
      });
    });

    it('should remove objects created for test', function (done) {
      async.map([_100kbObjectName, _100kbObjectNameCopy], function (objectName, cb) {
        return client.removeObject(bucketName, objectName, cb);
      }, done);
    });
  });

  describe('listIncompleteUploads removeIncompleteUpload', function () {
    it('should create multipart request', function (done) {
      client.initiateNewMultipartUpload(bucketName, _6mbObjectName, 'application/octet-stream', done);
    });
    it('should list incomplete upload', function (done) {
      // Minio's ListIncompleteUploads returns an empty list, so skip this on non-AWS.
      // See: https://github.com/minio/minio/commit/75c43bfb6c4a2ace
      if (!client.host.includes('s3.amazonaws.com')) {
        this.skip();
      }

      var found = false;
      client.listIncompleteUploads(bucketName, _6mbObjectName, true).on('error', function (e) {
        return done(e);
      }).on('data', function (data) {
        if (data.key === _6mbObjectName) found = true;
      }).on('end', function () {
        if (found) return done();
        done(new Error(_6mbObjectName + ' not found during listIncompleteUploads'));
      });
    });
    it('should delete incomplete upload', function (done) {
      client.removeIncompleteUpload(bucketName, _6mbObjectName).then(done)['catch'](done);
    });
  });

  describe('fPutObject fGetObject', function () {
    var tmpFileUpload = tmpDir + '/' + _6mbObjectName;
    var tmpFileDownload = tmpDir + '/' + _6mbObjectName + '.download';

    it('should create ' + tmpFileUpload, function () {
      return fs.writeFileSync(tmpFileUpload, _6mb);
    });

    it('should upload object using fPutObject', function (done) {
      return client.fPutObject(bucketName, _6mbObjectName, tmpFileUpload, '', done);
    });

    it('should download object using fGetObject', function (done) {
      return client.fGetObject(bucketName, _6mbObjectName, tmpFileDownload, done);
    });

    it('should verify checksum', function (done) {
      var md5sum = crypto.createHash('md5').update(fs.readFileSync(tmpFileDownload)).digest('hex');
      if (md5sum === _6mbmd5) return done();
      return done(new Error('md5sum mismatch'));
    });

    it('should upload object using fPutObject, as promise', function (done) {
      client.removeObject(bucketName, _6mbObjectName).then(function () {
        return client.fPutObject(bucketName, _6mbObjectName, tmpFileUpload, '');
      }).then(function () {
        return done();
      })['catch'](done);
    });

    it('should download object using fGetObject, as promise', function (done) {
      client.fGetObject(bucketName, _6mbObjectName, tmpFileDownload).then(function () {
        return done();
      })['catch'](done);
    });

    it('should verify checksum', function (done) {
      var md5sum = crypto.createHash('md5').update(fs.readFileSync(tmpFileDownload)).digest('hex');
      if (md5sum === _6mbmd5) return done();
      return done(new Error('md5sum mismatch'));
    });

    it('should remove files and objects created', function (done) {
      fs.unlinkSync(tmpFileUpload);
      fs.unlinkSync(tmpFileDownload);
      client.removeObject(bucketName, _6mbObjectName, done);
    });
  });

  describe('fGetObject-resume', function () {
    var localFile = tmpDir + '/' + _5mbObjectName;
    it('should upload object', function (done) {
      var stream = readableStream(_5mb);
      client.putObject(bucketName, _5mbObjectName, stream, _5mb.length, '', done);
    });
    it('should simulate a partially downloaded file', function () {
      var tmpFile = tmpDir + '/' + _5mbObjectName + '.' + _5mbmd5 + '.part.minio-js';
      // create a partial file
      fs.writeFileSync(tmpFile, _100kb);
    });
    it('should resume the download', function (done) {
      return client.fGetObject(bucketName, _5mbObjectName, localFile, done);
    });
    it('should verify md5sum of the downloaded file', function (done) {
      var data = fs.readFileSync(localFile);
      var hash = crypto.createHash('md5').update(data).digest('hex');
      if (hash === _5mbmd5) return done();
      done(new Error('md5 of downloaded file does not match'));
    });
    it('should remove tmp files', function (done) {
      fs.unlinkSync(localFile);
      client.removeObject(bucketName, _5mbObjectName, done);
    });
  });

  describe('bucket policy', function () {
    var policies = [Policy.READONLY, Policy.WRITEONLY, Policy.READWRITE];

    // Iterate through the basic policies ensuring it can set and check each of them.
    policies.forEach(function (policy) {
      it('should set bucket policy to ' + policy + ', then verify', function (done) {
        client.setBucketPolicy(bucketName, '', policy, function (err) {
          if (err) return done(err);

          // Check using the client.
          client.getBucketPolicy(bucketName, '', function (err, response) {
            if (err) return done(err);

            if (response != policy) {
              return done(new Error('policy is incorrect (' + response + ' != ' + policy + ')'));
            }

            done();
          });
        });
      });
    });

    it('should set and get bucket policy as promise', function (done) {
      client.setBucketPolicy(bucketName, '', Policy.READONLY).then(function () {
        return client.getBucketPolicy(bucketName, '');
      }).then(function (response) {
        if (response != Policy.READONLY) throw new Error('policy is incorrect (' + response + ' != ' + Policy.READONLY + ')');
      }).then(function () {
        return done();
      })['catch'](done);
    });

    it('should set bucket policy only on a prefix', function (done) {
      // READONLY also works, as long as it can read.
      var policy = Policy.READWRITE;

      // Set the bucket policy on `prefix`, and check to make sure it only
      // returns this bucket policy when asked about `prefix`.
      client.setBucketPolicy(bucketName, 'prefix', policy, function (err) {
        if (err) return done(err);

        // Check on the prefix.
        client.getBucketPolicy(bucketName, 'prefix', function (err, response) {
          if (err) return done(err);

          if (response != policy) {
            return done(new Error('policy is incorrect (' + response + ' != ' + policy + ')'));
          }

          // Check on a different prefix.
          client.getBucketPolicy(bucketName, 'wrongprefix', function (err, response) {
            if (err) return done(err);

            if (response == policy) {
              return done(new Error('policy is incorrect (' + response + ' == ' + policy + ')'));
            }

            done();
          });
        });
      });
    });

    it('should set bucket policy to none, then error', function (done) {
      client.setBucketPolicy(bucketName, '', Policy.NONE, function (err) {
        if (err) return done(err);

        // Check using the client — this should error.
        client.getBucketPolicy(bucketName, '', function (err) {
          if (!err) return done(new Error('getBucketPolicy should error'));

          if (!/does not have a bucket policy/.test(err.message) && !/bucket policy does not exist/.test(err.message)) {
            return done(new Error('error message is incorrect (' + err.message + ')'));
          }
          done();
        });
      });
    });
  });

  describe('presigned operations', function () {
    it('should upload using presignedUrl', function (done) {
      client.presignedPutObject(bucketName, _1byteObjectName, 1000, function (e, presignedUrl) {
        if (e) return done(e);
        var transport = http;
        var options = _.pick(url.parse(presignedUrl), ['hostname', 'port', 'path', 'protocol']);
        options.method = 'PUT';
        options.headers = {
          'content-length': _1byte.length
        };
        if (options.protocol === 'https:') transport = https;
        var request = transport.request(options, function (response) {
          if (response.statusCode !== 200) return done(new Error('error on put : ' + response.statusCode));
          response.on('error', function (e) {
            return done(e);
          });
          response.on('end', function () {
            return done();
          });
          response.on('data', function () {});
        });
        request.on('error', function (e) {
          return done(e);
        });
        request.write(_1byte);
        request.end();
      });
    });

    it('should attempt upload using promise presignedURL', function (done) {
      // negative values should trigger an error
      client.presignedPutObject(bucketName, _1byteObjectName, -123).then(function () {
        done(new Error('negative values should trigger an error'));
      })['catch'](function () {
        return done();
      });
    });

    it('should download using presignedUrl', function (done) {
      client.presignedGetObject(bucketName, _1byteObjectName, 1000, function (e, presignedUrl) {
        if (e) return done(e);
        var transport = http;
        var options = _.pick(url.parse(presignedUrl), ['hostname', 'port', 'path', 'protocol']);
        options.method = 'GET';
        if (options.protocol === 'https:') transport = https;
        var request = transport.request(options, function (response) {
          if (response.statusCode !== 200) return done(new Error('error on put : ' + response.statusCode));
          var error = null;
          response.on('error', function (e) {
            return done(e);
          });
          response.on('end', function () {
            return done(error);
          });
          response.on('data', function (data) {
            if (data.toString() !== _1byte.toString()) {
              error = new Error('content mismatch');
            }
          });
        });
        request.on('error', function (e) {
          return done(e);
        });
        request.end();
      });
    });

    it('should attempt download using promise presignedURL', function (done) {
      client.presignedGetObject(bucketName, 'this.does.not.exist', 2938).then(assert.fail)['catch'](function () {
        return done();
      });
    });

    it('should set response headers to expected values during download for presignedUrl', function (done) {
      var respHeaders = {
        'response-content-type': 'text/html',
        'response-content-language': 'en',
        'response-expires': 'Sun, 07 Jun 2020 16:07:58 GMT',
        'response-cache-control': 'No-cache',
        'response-content-disposition': 'attachment; filename=testing.txt',
        'response-content-encoding': 'gzip'
      };
      client.presignedGetObject(bucketName, _1byteObjectName, 1000, respHeaders, function (e, presignedUrl) {
        if (e) return done(e);
        var transport = http;
        var options = _.pick(url.parse(presignedUrl), ['hostname', 'port', 'path', 'protocol']);
        options.method = 'GET';
        if (options.protocol === 'https:') transport = https;
        var request = transport.request(options, function (response) {
          if (response.statusCode !== 200) return done(new Error('error on get : ' + response.statusCode));
          if (respHeaders['response-content-type'] != response.headers['content-type']) {
            return done(new Error('content-type header mismatch'));
          }
          if (respHeaders['response-content-language'] != response.headers['content-language']) {
            return done(new Error('content-language header mismatch'));
          }
          if (respHeaders['response-expires'] != response.headers['expires']) {
            return done(new Error('expires header mismatch'));
          }
          if (respHeaders['response-cache-control'] != response.headers['cache-control']) {
            return done(new Error('cache-control header mismatch'));
          }
          if (respHeaders['response-content-disposition'] != response.headers['content-disposition']) {
            return done(new Error('content-disposition header mismatch'));
          }
          if (respHeaders['response-content-encoding'] != response.headers['content-encoding']) {
            return done(new Error('content-encoding header mismatch'));
          }
          response.on('data', function () {});
          done();
        });
        request.on('error', function (e) {
          return done(e);
        });
        request.end();
      });
    });

    it('should upload using presigned POST', function (done) {
      var policy = client.newPostPolicy();
      policy.setKey(_1byteObjectName);
      policy.setBucket(bucketName);
      var expires = new Date();
      expires.setSeconds(24 * 60 * 60 * 10);
      policy.setExpires(expires);

      client.presignedPostPolicy(policy, function (e, urlStr, formData) {
        if (e) return done(e);
        var req = superagent.post('' + urlStr);
        _.each(formData, function (value, key) {
          return req.field(key, value);
        });
        req.attach('file', new Buffer([_1byte]), 'test');
        req.end(function (e) {
          if (e) return done(e);
          done();
        });
        req.on('error', function (e) {
          return done(e);
        });
      });
    });

    it('should attempt post policy with promise', function (done) {
      client.presignedPostPolicy(null).then(function () {
        done(new Error('null policy should fail'));
      })['catch'](function () {
        return done();
      });
    });

    it('should delete uploaded objects', function (done) {
      client.removeObject(bucketName, _1byteObjectName, done);
    });
  });

  describe('listObjects', function () {
    var listObjectPrefix = 'miniojsPrefix';
    var listObjectsNum = 10;
    var objArray = [];
    var listArray = [];

    it('should create ' + listObjectsNum + ' objects', function (done) {
      _.times(listObjectsNum, function (i) {
        return objArray.push(listObjectPrefix + '.' + i);
      });
      objArray = objArray.sort();
      async.mapLimit(objArray, 20, function (objectName, cb) {
        return client.putObject(bucketName, objectName, readableStream(_1byte), _1byte.length, '', cb);
      }, done);
    });

    it('should list objects', function (done) {
      client.listObjects(bucketName, '', true).on('error', done).on('end', function () {
        if (_.isEqual(objArray, listArray)) return done();
        return done(new Error('listObjects lists ' + listArray.length + ' objects, expected ' + listObjectsNum));
      }).on('data', function (data) {
        listArray.push(data.name);
      });
    });

    it('should list objects using v2 api', function (done) {
      listArray = [];
      client.listObjectsV2(bucketName, '', true).on('error', done).on('end', function () {
        if (_.isEqual(objArray, listArray)) return done();
        return done(new Error('listObjects lists ' + listArray.length + ' objects, expected ' + listObjectsNum));
      }).on('data', function (data) {
        listArray.push(data.name);
      });
    });

    it('should remove objects', function (done) {
      async.mapLimit(listArray, 20, function (objectName, cb) {
        return client.removeObject(bucketName, objectName, cb);
      }, done);
    });
  });

  function readableStream(data) {
    var s = new stream.Readable();
    s._read = function () {};
    s.push(data);
    s.push(null);
    return s;
  }

  describe('bucket notifications', function () {
    describe('#listenBucketNotification', function () {
      before(function () {
        // listenBucketNotification only works on Minio, so skip if
        // the host is Amazon.
        if (client.host.includes('s3.amazonaws.com')) {
          this.skip();
        }
      });

      it('should forward error with bad events', function (done) {
        var poller = client.listenBucketNotification(bucketName, 'photos/', '.jpg', ['bad']);
        poller.on('error', function (error) {
          assert.match(error.message, /A specified event is not supported for notifications./);
          assert.equal(error.code, 'InvalidArgument');

          done();
        });
      });
      it('should give exactly one event for single action', function (done) {
        var poller = client.listenBucketNotification(bucketName, '', '', ['s3:ObjectCreated:*']);
        var records = 0;
        poller.on('notification', function (record) {
          records++;

          assert.equal(record.eventName, 's3:ObjectCreated:Put');
          assert.equal(record.s3.bucket.name, bucketName);
          assert.equal(record.s3.object.key, objectName);
        });
        client.putObject(bucketName, objectName, 'stringdata', function (err) {
          if (err) return done(err);
          // It polls every five seconds, so wait for two-ish polls, then end.
          setTimeout(function () {
            assert.equal(records, 1);
            poller.stop();
            client.removeObject(bucketName, objectName, done);
          }, 11 * 1000);
        });
      });

      // This test is very similar to that above, except it does not include
      // Minio.ObjectCreatedAll in the config. Thus, no events should be emitted.
      it('should give no events for single action', function (done) {
        var poller = client.listenBucketNotification(bucketName, '', '', ['s3:ObjectRemoved:*']);
        poller.on('notification', assert.fail);

        client.putObject(bucketName, objectName, 'stringdata', function (err) {
          if (err) return done(err);
          // It polls every five seconds, so wait for two-ish polls, then end.
          setTimeout(function () {
            poller.stop();
            poller.removeAllListeners('notification');
            // clean up object now
            client.removeObject(bucketName, objectName, done);
          }, 11 * 1000);
        });
      });
    });
  });
});
//# sourceMappingURL=functional-tests.js.map
