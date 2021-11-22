// # Frontend Route tests
// As it stands, these tests depend on the database, and as such are integration tests.
// Mocking out the models to not touch the DB would turn these into unit tests, and should probably be done in future,
// But then again testing real code, rather than mock code, might be more useful...
const should = require('should');

const sinon = require('sinon');
const supertest = require('supertest');
const cheerio = require('cheerio');
const _ = require('lodash');
const testUtils = require('../../utils');
const configUtils = require('../../utils/configUtils');
const config = require('../../../core/shared/config');
const ghost = testUtils.startGhost;
let request;

describe('Frontend Routing', function () {
    function doEnd(done) {
        return function (err, res) {
            if (err) {
                return done(err);
            }

            should.not.exist(res.headers['x-cache-invalidate']);
            should.not.exist(res.headers['X-CSRF-Token']);
            should.not.exist(res.headers['set-cookie']);
            should.exist(res.headers.date);

            done();
        };
    }

    function addPosts(done) {
        testUtils.clearData().then(function () {
            return testUtils.initData();
        }).then(function () {
            return testUtils.fixtures.insertPostsAndTags();
        }).then(function () {
            done();
        });
    }

    afterEach(function () {
        sinon.restore();
    });

    before(function () {
        return ghost()
            .then(function () {
                request = supertest.agent(config.get('url'));
            });
    });

    describe('Test with Initial Fixtures', function () {
        describe('Error', function () {
            it('should 404 for unknown post with invalid characters', function (done) {
                request.get('/$pec+acular~/')
                    .expect('Cache-Control', testUtils.cacheRules.private)
                    .expect(404)
                    .expect(/Page not found/)
                    .end(doEnd(done));
            });

            it('should 404 for unknown frontend route', function (done) {
                request.get('/spectacular/marvellous/')
                    .set('Accept', 'application/json')
                    .expect('Cache-Control', testUtils.cacheRules.private)
                    .expect(404)
                    .expect(/Page not found/)
                    .end(doEnd(done));
            });

            it('should 404 for encoded char not 301 from uncapitalise', function (done) {
                request.get('/|/')
                    .expect('Cache-Control', testUtils.cacheRules.private)
                    .expect(404)
                    .expect(/Page not found/)
                    .end(doEnd(done));
            });
        });

        describe('Default Redirects (clean URLS)', function () {
            it('Single post should redirect without slash', function (done) {
                request.get('/welcome')
                    .expect('Location', '/welcome/')
                    .expect('Cache-Control', testUtils.cacheRules.year)
                    .expect(301)
                    .end(doEnd(done));
            });

            it('Single post should redirect uppercase', function (done) {
                request.get('/Welcome/')
                    .expect('Location', '/welcome/')
                    .expect('Cache-Control', testUtils.cacheRules.year)
                    .expect(301)
                    .end(doEnd(done));
            });

            it('Single post should sanitize double slashes when redirecting uppercase', function (done) {
                request.get('///Google.com/')
                    .expect('Location', '/google.com/')
                    .expect('Cache-Control', testUtils.cacheRules.year)
                    .expect(301)
                    .end(doEnd(done));
            });

            it('AMP post should redirect without slash', function (done) {
                request.get('/welcome/amp')
                    .expect('Location', '/welcome/amp/')
                    .expect('Cache-Control', testUtils.cacheRules.year)
                    .expect(301)
                    .end(doEnd(done));
            });

            it('AMP post should redirect uppercase', function (done) {
                request.get('/Welcome/AMP/')
                    .expect('Location', '/welcome/amp/')
                    .expect('Cache-Control', testUtils.cacheRules.year)
                    .expect(301)
                    .end(doEnd(done));
            });
        });
    });

    describe('Test with added posts', function () {
        before(addPosts);

        describe('Static page', function () {
            it('should respond with html', function (done) {
                request.get('/static-page-test/')
                    .expect('Content-Type', /html/)
                    .expect('Cache-Control', testUtils.cacheRules.public)
                    .expect(200)
                    .end(function (err, res) {
                        const $ = cheerio.load(res.text);

                        should.not.exist(res.headers['x-cache-invalidate']);
                        should.not.exist(res.headers['X-CSRF-Token']);
                        should.not.exist(res.headers['set-cookie']);
                        should.exist(res.headers.date);

                        $('title').text().should.equal('This is a static page');
                        $('body.page-template').length.should.equal(1);
                        $('article.post').length.should.equal(1);

                        doEnd(done)(err, res);
                    });
            });

            it('should redirect without slash', function (done) {
                request.get('/static-page-test')
                    .expect('Location', '/static-page-test/')
                    .expect('Cache-Control', testUtils.cacheRules.year)
                    .expect(301)
                    .end(doEnd(done));
            });

            describe('edit', function () {
                it('should redirect without slash', function (done) {
                    request.get('/static-page-test/edit')
                        .expect('Location', '/static-page-test/edit/')
                        .expect('Cache-Control', testUtils.cacheRules.year)
                        .expect(301)
                        .end(doEnd(done));
                });

                it('should redirect to editor', function (done) {
                    request.get('/static-page-test/edit/')
                        .expect('Location', /ghost\/#\/editor\/\w+/)
                        .expect('Cache-Control', testUtils.cacheRules.public)
                        .expect(302)
                        .end(doEnd(done));
                });

                it('should 404 for non-edit parameter', function (done) {
                    request.get('/static-page-test/notedit/')
                        .expect('Cache-Control', testUtils.cacheRules.private)
                        .expect(404)
                        .expect(/Page not found/)
                        .end(doEnd(done));
                });
            });

            describe('edit with admin redirects disabled', function () {
                before(function (done) {
                    configUtils.set('admin:redirects', false);

                    ghost({forceStart: true})
                        .then(function () {
                            request = supertest.agent(config.get('url'));
                            addPosts(done);
                        });
                });

                after(function (done) {
                    configUtils.restore();

                    ghost({forceStart: true})
                        .then(function () {
                            request = supertest.agent(config.get('url'));
                            addPosts(done);
                        });
                });

                it('should redirect without slash', function (done) {
                    request.get('/static-page-test/edit')
                        .expect('Location', '/static-page-test/edit/')
                        .expect('Cache-Control', testUtils.cacheRules.year)
                        .expect(301)
                        .end(doEnd(done));
                });

                it('should not redirect to editor', function (done) {
                    request.get('/static-page-test/edit/')
                        .expect(404)
                        .expect('Cache-Control', testUtils.cacheRules.private)
                        .end(doEnd(done));
                });
            });

            describe('amp', function () {
                it('should 404 for amp parameter', function (done) {
                    // NOTE: only post pages are supported so the router doesn't have a way to distinguish if
                    //       the request was done after AMP 'Page' or 'Post'
                    request.get('/static-page-test/amp/')
                        .expect('Cache-Control', testUtils.cacheRules.private)
                        .expect(404)
                        .expect(/Post not found/)
                        .end(doEnd(done));
                });
            });
        });

        describe('Post with Ghost in the url', function () {
            // All of Ghost's admin depends on the /ghost/ in the url to work properly
            // Badly formed regexs can cause breakage if a post slug starts with the 5 letters ghost
            it('should retrieve a blog post with ghost at the start of the url', function (done) {
                request.get('/ghostly-kitchen-sink/')
                    .expect('Cache-Control', testUtils.cacheRules.public)
                    .expect(200)
                    .end(doEnd(done));
            });
        });
    });
});
