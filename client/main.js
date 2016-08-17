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
            importance: 50,
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
                { name: TAPi18n.__('cve'), contents: "" },
                { name: TAPi18n.__('owasptop10'), contents: "" },
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


Router.route('edit_current_project', {
    name: 'edit_current_project',
    path: '/edit/project',
    template: 'edit_project',
    data: function () {
        projectDeps.depend();
        if (typeof this.project === "undefined") {
            this.project = Projects.findOne({name: Session.get("project")});
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

Session.setDefault("project", "");
Session.setDefault("links", false);
Deps.autorun(function() {
    if (Session.get("links")) {
        $('.vuln').addClass('hand');
    } else {
        $('.vuln').removeClass('hand');
    }
});

Template.main.events({
    'change #project'(event, instance) {
        Session.set("project", event.target.value);
    },
    'click #logout'(event, instance) {
        Meteor.logout();
    },
    'click .vuln'(events, instance) {
        if (Session.get("links")) {
            Router.go("/edit/vuln/"+this._id);
        }
    },
});

Template.export.events({
    'change #links'(event, instance) {
        Session.set("links", $('#links')[0].checked);
    },
    'click #select_copy'(event, instance) {
        selectText('selectable');
        try {
            document.execCommand('copy');
        } catch (err) {
            console.log('Oops, unable to copy');
        }
    },
});

Template.edit_project.events({
    'click #save'(event, instance) {
        oldProject = JSON.stringify(orderObject(this));
        Projects.update(this._id, this);
        Router.go("/");
        vulnProject.changed();
    },
    'click #delete'(event, instance) {
        Projects.remove(this._id);
        Router.go("/");
        Session.set("project", "");
        projectDeps.changed();
    },
    'keyup #name'(event, instance) {
        this.name = event.target.value;
        projectDeps.changed();
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
        if (name===Session.get("project")) return "selected";
        return "";
    }
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
            {name:TAPi18n.__('i_critical'), value: 50},
            {name:TAPi18n.__('i_high'), value: 40},
            {name:TAPi18n.__('i_medium'), value: 30},
            {name:TAPi18n.__('i_low'), value: 20},
            {name:TAPi18n.__('i_info'), value: 10},
    ];
};

Handlebars.registerHelper('getImportanceName', function (i) {
    var p = priorities();
    for (n in p) {
        if (p[n].value==i) return p[n].name;
    }
    return i.toString();
});

Handlebars.registerHelper('getImportanceRGB', function (i) {
    var p = priorities();
    var max=0;
    var min=999999;
    for (n in p) {
        if (p[n].value>max) max=p[n].value;
        if (p[n].value<min) min=p[n].value;
    }
    max=max-min;
    var GB=Math.round(255-(i-min)*255/max);
    
    return "RGB(255,"+GB.toString()+","+GB.toString()+")";
});

Template.list.events({
    'click .hand'(event, instance) {
        Router.go($(event.target.parentElement).data("href"));
    },
    'click .project_link'(event, instance) {
        Session.set("project", event.target.innerText);
    },
});

Template.vuln.helpers({
    links_hand: function () {
        if (Session.get("links")) return "hand";
        return "";
    }
});

Template.edit_vuln.helpers({
    hasCvss: function() {
        return this.hasCvss;
    },
    priorites: function() {
        return priorities();
    },
    i_selected: function(val, opt) {
        if (val==opt) return "selected";
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
        var p = Template.parentData();
        var i = p.sections.indexOf(this);
        if (i!=-1) {
            var copy = p.sections.slice();
            copy.splice(i,1);
            p.sections = copy;
        }
        console.log($(event.target).data("id"));
        //$("#"+$(event.target).data("id")).summernote("destroy");
        vulnDeps.changed();
    },
    'change #hasCvss'(event, instance) {
        this.hasCvss= event.target.checked;
        vulnDeps.changed();
    },
    'change #importance'(event, instance) {
        this.importance= parseInt(event.target.value);
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

Router.route('export', {
    path: '/export',
    template: 'export',
    onBeforeAction: function () {
        var currentUser = Meteor.userId();
        if(!currentUser){
            Router.go('/login');
        }
        this.next();
    }
});


var vulns = function(project) {
    projectDeps.depend();
    if (project=="") return Vulns.find({ }, {sort: {importance: -1, score: -1}}).fetch(); 
    return Vulns.find({ "project": project }, {sort: {importance: -1, score: -1}}).fetch(); 
};

var selectText = function (containerid) {
    if (document.selection) {
        var range = document.body.createTextRange();
        range.moveToElementText(document.getElementById(containerid));
        range.select();
    } else if (window.getSelection) {
        var range = document.createRange();
        range.selectNode(document.getElementById(containerid));
        window.getSelection().addRange(range);
    }
};

Template.export.helpers({
    vulns: function() {
        console.log(Session.get("project"));
        return vulns(Session.get("project"));
    },
});


Template.list.helpers({
    projects: function() {
        if (Session.get("project")=="") {
            var ret = [];
            console.log("JEST");
            Projects.find({}).fetch().forEach(function (p) {
                console.log(JSON.stringify(p));
                ret.push(p.name);
            });
            console.log(ret);
            return ret;
        } else {
            return [ Session.get("project") ];
        } 
    },
    vulns: function(name) {
        return vulns(name);
    }
});

Template.export.helpers({
    links_checked: function() {
        if (Session.get("links")) return "checked";
        return "";
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
