import setupDb from '../fixtures/global-setup';

export default function setup() {
  process.env.TEST_DATABASE_URL ??= 'postgres://postgres@127.0.0.1:54329/bsp_e2e';
  setupDb();
}
