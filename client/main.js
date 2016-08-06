import { Template } from 'meteor/templating';
import { ReactiveVar } from 'meteor/reactive-var';
import { Session } from 'meteor/session'

import './main.html';
import { Vulns, Projects } from '../imports/api/vulns.js';

export const vulnDeps = new Deps.Dependency;
export const projectDeps = new Deps.Dependency;

var oldVuln="";
var oldProject="";

Template.body.onCreated(function bodyOnCreated() {
    Meteor.subscribe('vulns');
    Meteor.subscribe('projects');
});


Router.configure({
    layoutTemplate: 'main'
});


Router.route('login', {
    path: '/login',
    template: 'login'
});
             
Router.route('new', {
    path: '/new/vuln',
    onBeforeAction: function () {
        var currentUser = Meteor.userId();
        if(!currentUser){
            Router.go('/login');
        }

        var o = Vulns.insert({
            title: TAPi18n.__('vulnerability'),
            score: 0,
            project: Session.get("project"),
            cvss3: {
                "AV": { value: "N", comment: "" },
                "AC": { value: "L", comment: "" },
                "PR": { value: "N", comment: "" },
                "UI": { value: "N", comment: "" },
                "S": { value: "U", comment: "" },
                "C": { value: "N", comment: "" },
                "I": { value: "N", comment: "" },
                "A": { value: "N", comment: "" },
            },
            hasCvss: true,
            sections: [
                { name: TAPi18n.__('impact'), contents: "" },
                { name: TAPi18n.__('verify'), contents: "" },
                { name: TAPi18n.__('recommendations'), contents: "" },
            ]
        });
        Router.go('/edit/vuln/'+o);
  }
});

Router.route('newproject', {
    path: '/new/project',
    onBeforeAction: function () {
        var currentUser = Meteor.userId();
        if(!currentUser){
            Router.go('/login');
        }
        var o = Projects.insert({
            name: "Project"
        });
        Router.go('/edit/project/'+o);
    }
});

orderObject = function(unordered) {
    const ordered = {};
    Object.keys(unordered).sort().forEach(function(key) {
        ordered[key] = unordered[key];
    });
    return ordered;
};


Router.route('edit_project', {
    name: 'edit_project',
    path: '/edit/project/:_id',
    template: 'edit_project',
    data: function () {
        projectDeps.depend();
        if (typeof this.project === "undefined") {
            this.project = Projects.findOne(Router.current().params._id);
            if (typeof this.project !== "undefined") oldProject=JSON.stringify(orderObject(this.project));
        } else if (oldProject!==JSON.stringify(orderObject(Projects.findOne(Router.current().params._id)))) {
            alert(TAPi18n.__('document_changed'));
        }
        return this.project;
    },
    onBeforeAction: function () {
        var currentUser = Meteor.userId();
        if(!currentUser){
            Router.go('/login');
        }
        this.next();
    }
});

Template.main.events({
    'change #project'(event, instance) {
        Session.set("project", event.target.value);
    },
    'click #logout'(event, instance) {
        Meteor.logout();
    }
});

Template.edit_project.events({
    'click #save'(event, instance) {
        oldProject = JSON.stringify(orderObject(this));
        Projects.update(this._id, this);
        Router.go("/");
    },
    'click #delete'(event, instance) {
        Projects.remove(this._id);
        Router.go("/");
    },
    'keyup #name'(event, instance) {
        this.name = event.target.value;
        vulnProject.changed();
    },
});



Router.route('edit_vuln', {
    name: 'edit_vuln',
    path: '/edit/vuln/:_id',
    template: 'edit_vuln',
    data: function () {
        vulnDeps.depend();
        if (typeof this.vuln === "undefined") {
            this.vuln = Vulns.findOne(Router.current().params._id);
            if (typeof this.vuln !== "undefined") oldVuln=JSON.stringify(orderObject(this.vuln));
        } else if (oldVuln!==JSON.stringify(orderObject(Vulns.findOne(Router.current().params._id)))) {
            alert(TAPi18n.__('document_changed'));
        }
        return this.vuln;
    },
    onStop: function() {
        $('.note-editor').remove();
    },
    onBeforeAction: function () {
        var currentUser = Meteor.userId();
        if(!currentUser){
            Router.go('/login');
        }
        this.next();
    }
});


var counter=0;
Handlebars.registerHelper('getId', function () {
    return counter++;
});

Template.main.helpers({
    projects: function() {
        return Projects.find({}).fetch();
    },
    loggedin: function() {
        if (Meteor.userId() != null) {
            return true;
        }
        return false;
    },
    selectedProject: function(name) {
        Session.setDefault("project",name);
        if (name===Session.get("project")) return "selected";
        return "";
    },
});

Template.login.events({
    'submit form': function(event){
        event.preventDefault();
        var email = $('[name=email]').val();
        var password = $('[name=password]').val();
        console.log(email+" "+password);
        Meteor.loginWithPassword(email, password, function(error){
            if(error){
                $('#login_error')[0].innerText=TAPi18n.__('login_error');
            } else {
                Router.go("/");
            }
        });
    },
});


var priorities=function () {
    return [
            {name:TAPi18n.__('i_critical'), value: "c"},
            {name:TAPi18n.__('i_high'), value: "h"},
            {name:TAPi18n.__('i_medium'), value: "m"},
            {name:TAPi18n.__('i_low'), value: "l"},
            {name:TAPi18n.__('i_info'), value: "i"},
    ];
};

Template.vuln.helpers({
    getImportanceName: function(i) {
        var p = priorities();
        for (n in p) {
            if (p[n].value===i) return p[n].name;
        }
        return "";
    },
});

Template.edit_vuln.helpers({
    hasCvss: function() {
        return this.hasCvss;
    },
    priorites: function() {
        return priorities();
    },
    i_selected: function(val, opt) {
        if (val===opt) return "selected";
        return "";
    },
});

setupSummernote = function(id) {
    $('#'+id).summernote({callbacks: {
        onKeyup: function(e) {
            var data = Blaze.getData($("#"+this.id)[0]);
            data.content = $('#'+this.id).summernote('code');
            vulnDeps.changed();
        }
    }});
};

Template.edit_vuln.events({
    'keyup .section_content'(event, instance) {
        console.log('jest');
        console.log(JSON.stringify(this));
    },
    'click #add'(event, instance) {
        if (typeof this.sections === "undefined") this.sections=[];
        this.sections.push({ name: "New section", content: ""});
        vulnDeps.changed();
    },
    'click #save'(event, instance) {
        oldVuln = JSON.stringify(orderObject(this));
        Vulns.update(this._id, this);
        Router.go("/");
    },
    'click #delete'(event, instance) {
        Vulns.remove(this._id);
        Router.go("/");
    },
    'click #delete_section'(event, instance) {
        var s = Template.parentData().sections;
        var i = s.indexOf(this);
        if (i!=-1) s.splice(i,1);
        vulnDeps.changed();
    },
    'change #hasCvss'(event, instance) {
        this.hasCvss= event.target.checked;
        vulnDeps.changed();
    },
    'change #importance'(event, instance) {
        this.importance= event.target.value;
        vulnDeps.changed();
    },
    'keyup .section_name'(event, instance) {
        this.name = event.target.value;
        vulnDeps.changed();
    },
    'keyup .section_content'(event, instance) {
        this.content = event.target.value;
        vulnDeps.changed();
    },
    'keyup #title'(event, instance) {
        this.title = event.target.value;
        vulnDeps.changed();
    },
    'keyup #projectname'(event, instance) {
        this.project = event.target.value;
        vulnDeps.changed();
    },
});



Router.route('default', {
    path: '/',
    template: 'list',
    onBeforeAction: function () {
        var currentUser = Meteor.userId();
        if(!currentUser){
            Router.go('/login');
        }
        this.next();
    }
});



Template.list.helpers({
    vulns: function() {
        return Vulns.find({ project: Session.get("project") }).fetch();
    },
});



Template.hello.onCreated(function helloOnCreated() {
  // counter starts at 0
  this.counter = new ReactiveVar(0);
});

Template.hello.helpers({
  counter() {
    return Template.instance().counter.get();
  },
});

Template.hello.events({
  'click button'(event, instance) {
    // increment the counter when button is clicked
    instance.counter.set(instance.counter.get() + 1);
  },
});


Meteor.startup(function () {
    Session.set("showLoadingIndicator", true);
    
    TAPi18n.setLanguage("pl")
        .done(function () {
            Session.set("showLoadingIndicator", false);
        })
        .fail(function (error_message) {
            // Handle the situation
            console.log(error_message);
        });
});
