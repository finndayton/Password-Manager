"use strict";

var expect = require('expect.js');
const { Keychain } = require('../password-manager');

describe('Password manager', async function() {
    this.timeout(5000);
    var password = "password123!";

    var kvs = {
        "service1": "value1",
        "service2": "value2",
        "service3": "value3"
    };

    describe('functionality', async function() {

        it('inits without an error', async function() {
            await Keychain.init(password);
        });

        it('can set and retrieve a password', async function() {
            let keychain = await Keychain.init(password);
            var url = 'www.stanford.edu';
            var pw = 'sunetpassword';
            await keychain.set(url, pw);
            expect(await keychain.get(url)).to.equal(pw);
        });

        it('can set and retrieve multiple passwords', async function() {
            let keychain = await Keychain.init(password);
            for (var k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            for (var k in kvs) {
                expect(await keychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('returns null for non-existent passwords', async function() {
            let keychain = await Keychain.init(password);
            for (var k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.get('www.stanford.edu')).to.be(null);
        });

        it('can remove a password', async function() {
            let keychain = await Keychain.init(password);
            for (var k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.remove('service1')).to.be(true);
            expect(await keychain.get('service1')).to.be(null);
        });

        it('returns false if there is no password for the domain being removed', async function() {
            let keychain = await Keychain.init(password);
            for (var k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.remove('www.stanford.edu')).to.be(false);
        });

        it('can dump and restore the database', async function() {
            let keychain = await Keychain.init(password);
            for (var k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            var data = await keychain.dump();
            var contents = data[0];
            var checksum = data[1];
            var newKeychain = await Keychain.load(password, contents, checksum);

            // Make sure it's valid JSON
            expect(async function() {
                JSON.parse(contents)
            }).not.to.throwException();
            for (var k in kvs) {
                expect(await keychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('fails to restore the database if checksum is wrong', async function() {
            let keychain = await Keychain.init(password);
            for (var k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            var data = await keychain.dump();
            var contents = data[0];
            var fakeChecksum = '3GB6WSm+j+jl8pm4Vo9b9CkO2tZJzChu34VeitrwxXM=';
            await expect(async function() { Keychain.load(password, contents, fakeChecksum)}).rejects;
        });

        it('returns false if trying to load with an incorrect password', async function() {
            let keychain = await Keychain.init(password);
            for (var k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            var data = await keychain.dump();
            var contents = data[0];
            var checksum = data[1];
            expect(async function() {await Keychain.load("fakepassword", contents, data[1])}).rejects;
        });
    });

    describe('security', async function() {

        // Very basic test to make sure you're not doing the most naive thing
        it("doesn't store domain names and passwords in the clear", async function() {
            let keychain = await Keychain.init(password);
            var url = 'www.stanford.edu';
            var pw = 'sunetpassword';
            await keychain.set(url, pw);
            var data = await keychain.dump();
            var contents = data[0];
            expect(contents).not.to.contain(password);
            expect(contents).not.to.contain(url);
            expect(contents).not.to.contain(pw);
        });

        // This test won't be graded directly -- it just exists to make sure your
        // dump include a kvs object with all your urls and passwords, because
        // we will be using that in other tests.
        it('includes a kvs object in the serialized dump', async function() {
            let keychain = await Keychain.init(password);
            for (var i = 0; i < 10; i++) {
                await keychain.set(String(i), String(i));
            }
            var data = await keychain.dump();
            var contents = data[0];
            var contentsObj = JSON.parse(contents);
            expect(contentsObj).to.have.key('kvs');
            expect(contentsObj.kvs).to.be.an('object');
            expect(Object.getOwnPropertyNames(contentsObj.kvs)).to.have.length(10);
        })

    });
});