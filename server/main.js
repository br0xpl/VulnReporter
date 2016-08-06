import { Meteor } from 'meteor/meteor';

import { Vulns, Projects } from '../imports/api/vulns.js';

Meteor.publish('vulns', function tasksPublication() {
    if (this.userId!=null) return Vulns.find();
    return null;
});

Meteor.publish('projects', function tasksPublication() {
    if (this.userId!=null) return Projects.find();
    return null;
});

Accounts.config({
  forbidClientAccountCreation : true
});

Meteor.startup(() => {
    // code to run on server at startup
    
});
