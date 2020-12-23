module.exports = {
  type: 'object',
  properties: {
    body: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email' },
        password: { type: 'string', minimum: 6 },
      },
      required: ['email', 'password'],
    },
  },
};
