import * as admin from 'firebase-admin';

export default (strapi) => {
  const oldServicesJwt = strapi.services.jwt;
  strapi.services.jwt = ({ strapi }) => ({
    ...oldServicesJwt(strapi),
    async verify(token) {
      return new Promise(async (resolve, reject) => {
        try {
          const decodedToken = await admin.auth().verifyIdToken(token, true);
          const strapiUid = decodedToken.strapiUid;

          if (strapiUid) {
            // check if user exists in strapi
            const findUserWithId = await strapi.query('plugin::users-permissions.user').findOne({
              where: { id: strapiUid },
              populate: ['role']
            });
            // check if user firebase uuid is correct
            if (findUserWithId && findUserWithId.id && findUserWithId.firebase_uuid === decodedToken.uid) {
              return resolve({ ...decodedToken, id: strapiUid });
            }

            // check if user firebase uuid is exist
            const findUserWithUuid = await strapi.query('plugin::users-permissions.user').findOne({
              where: { firebase_uuid: decodedToken.uid },
              populate: ['role']
            });
            if (findUserWithUuid && findUserWithUuid.id) {
              const userRecord = await admin.auth().getUser(decodedToken.uid);
              await admin.auth().setCustomUserClaims(decodedToken.uid, {
                ...userRecord.customClaims,
                strapiUid: findUserWithUuid.id,
              });
              return resolve({ ...decodedToken, id: findUserWithUuid.id });
            }
          }

          const user = await strapi.query('plugin::users-permissions.user').findOne({
            where: { firebase_uuid: decodedToken.uid },
            populate: ['role']
          });
          const userRecord = await admin.auth().getUser(decodedToken.uid);
          if (user) {
            await admin.auth().setCustomUserClaims(decodedToken.uid, {
              ...userRecord.customClaims,
              strapiUid: user.id,
            });
            return resolve({ ...decodedToken, id: user.id });
          }
          const advanced = await strapi.store({
            type: 'plugin',
            name: 'users-permissions',
            key: 'advanced'
          }).get();
          const defaultRole = await strapi.query('plugin::users-permissions.role').findOne({
            where: {
              type: advanced.default_role
            }
          });
          const result = await strapi.query('plugin::users-permissions.user').create({
            data: {
              username: decodedToken.uid,
              firebase_uuid: decodedToken.uid,
              confirmed: true,
              role: defaultRole.id,
              email: decodedToken.email ?? '',
              phone_number: decodedToken.phone_number ?? '',
            }
          });
          await admin.auth().setCustomUserClaims(decodedToken.uid, {
            ...userRecord.customClaims,
            strapiUid: result.id,
          });
          resolve({ ...decodedToken, id: result.id });
        } catch (error) {
          reject(error);
        }
      });
    }
  });

  return strapi;
}