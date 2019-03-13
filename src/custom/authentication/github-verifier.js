const { Verifier } = require('@feathersjs/authentication-oauth2');
const logger = require('../../logger');

class GithubVerifier extends Verifier {

  constructor(app, options = {}) {
    options.emailField = options.emailField || 'email';
    super(app, options);
  }

  _updateEntity(entity, data) {
    const options = this.options;
    const name = options.name;
    const id = entity[this.service.id];
    logger.debug(`Updating ${options.entity}: ${id}`);

    const newData = {
      ...data
    };
    delete newData[this.service.id];
    delete newData.accessToken;
    delete newData.refreshToken;

    return this.service.patch(id, newData, { oauth: { provider: name } });
  }

  _createEntity(data) {
    const options = this.options;
    const name = options.name;

    logger.debug(`Creating new ${options.entity} with ${options.idField}: ${data.id}`);
    return this.service.create({ ...data }, { oauth: { provider: name } });
  }

  verify(req, accessToken, refreshToken, profile, done) {
    logger.debug('Checking credentials');
    const options = this.options;

    const query = {
      $or: [
        { [options.idField]: profile.id },
        { [options.emailField]: { $in: (profile.emails || []).map(emailObj => emailObj.value) } },
      ],
      $limit: 1,
    };
    const data = {
      ...mapGithubUserToUser(profile, options),
      accessToken,
      refreshToken,
    };
    let existing;

    // Check request object for an existing entity
    if (req && req[options.entity]) {
      existing = req[options.entity];
    }

    // Check the request that came from a hook for an existing entity
    if (!existing && req && req.params && req.params[options.entity]) {
      existing = req.params[options.entity];
    }

    // If there is already an entity on the request object (ie. they are
    // already authenticated) attach the profile to the existing entity
    // because they are likely "linking" social accounts/profiles.
    if (existing) {
      return this._updateEntity(existing, data)
        .then(entity => done(null, entity))
        .catch(error => error ? done(error) : done(null, error));
    }

    // Find or create the user since they could have signed up via facebook.
    this.service
      .find({ query })
      .then(results => {
        return this._normalizeResult(results);
      })
      .then(entity => {
        return entity ? this._updateEntity(entity, data) : this._createEntity(data);
      })
      .then(entity => {
        const id = entity[this.service.id];
        const payload = { [`${this.options.entity}Id`]: id };
        done(null, entity, payload);
      })
      .catch(error => error ? done(error) : done(null, error));
  }
}

const mapGithubUserToUser = (profile, options) => {
  const {
    id,
    displayName,
    provider,
    username: userName,
    emails = [],
    photos = [],
    profileUrl,
  } = profile;

  return {
    [options.idField]: id,
    [options.emailField]: (emails[0] || {}).value,
    provider,
    displayName,
    userName,
    avatar: (photos[0] || {}).value,
    profileUrl,
    permissions: [ 'user:*' ]
  };
};

module.exports = GithubVerifier;
