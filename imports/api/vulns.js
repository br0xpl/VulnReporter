import { Mongo } from 'meteor/mongo';

export const Vulns = new Mongo.Collection('vulns');
export const Projects = new Mongo.Collection('projects');
