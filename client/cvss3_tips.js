
import { vulnDeps } from './main.js'

cvss3_tips = {
    // ==================
    // BASE Metrics Group
    // ==================
    "l_bsm" : "The Base metric group represents the intrinsic characteristics of a " +
        "vulnerability that are constant over time and across user environments. It is composed " +
        "of two sets of metrics: the Exploitability metrics and the Impact metrics. The " +
        "Exploitability metrics reflect the ease and technical means by which the vulnerability " +
        "can be exploited. That is, they represent characteristics of the thing that is " +
        "vulnerable, which we refer to formally as the vulnerable component. On the other hand, " +
        "the Impact metrics reflect the direct consequence of a successful exploit, and represent " +
        "the consequence to the thing that suffers the impact, which we refer to formally as the " +
        "impacted component.",
    "l_av" : "This metric reflects the context by which vulnerability exploitation is possible. " +
        "This metric value (and consequently the Base score) will be larger the more remote " +
        "(logically, and physically) an attacker can be in order to exploit the vulnerable " +
        "component.",
    // Attack Vector Buttons
    "b_avn" : "A vulnerability exploitable with Network access means the vulnerable component is " +
        "bound to the network stack and the attacker's path is through OSI layer 3 (the network " +
        "layer). Such a vulnerability is often termed 'remotely exploitable' and can be thought " +
        "of as an attack being exploitable one or more network hops away (e.g. across layer 3 " +
        "boundaries from routers).",
    "b_ava" : "A vulnerability exploitable with Adjacent Network access means the vulnerable " +
        "component is bound to the network stack, however the attack is limited to the same " +
        "shared physical (e.g. Bluetooth, IEEE 802.11), or logical (e.g. local IP subnet) " +
        "network, and cannot be performed across an OSI layer 3 boundary (e.g. a router).",
    "b_avl" : "A vulnerability exploitable with Local access means that the vulnerable component " +
        "is not bound to the network stack, and the attacker's path is via read/write/execute " +
        "capabilities. In some cases, the attacker may be logged in locally in order to exploit " +
        "the vulnerability, or may rely on User Interaction to execute a malicious file.",
    "b_avp" : "A vulnerability exploitable with Physical access requires the attacker to " +
        "physically touch or manipulate the vulnerable component, such as attaching an peripheral " +
        "device to a system.",
    // Access Complexity
    "l_ac" : "The Attack Complexity metric describes the conditions beyond the attacker's " +
        "control that must exist in order to exploit the vulnerability. As described below, such " +
        "conditions may require the collection of more information about the target, the presence " +
        "of certain system configuration settings, or computational exceptions.",
    "b_acl" : "Specialized access conditions or extenuating circumstances do not exist. An " +
        "attacker can expect repeatable success against the vulnerable component.",
    "b_ach" : "A successful attack depends on conditions beyond the attacker's control. That is, " +
        "a successful attack cannot be accomplished at will, but requires the attacker to invest " +
        "in some measurable amount of effort in preparation or execution against the vulnerable " +
        "component before a successful attack can be expected.",
    // Privileges Required
    "l_pr" : "This metric describes the level of privileges an attacker must possess before " +
        "successfully exploiting the vulnerability.",
    "b_prn" : "The attacker is unauthorized prior to attack, and therefore does not require any " +
        "access to settings or files to carry out an attack.",
    "b_prl" : "The attacker is authorized with (i.e. requires) privileges that provide basic " +
        "user capabilities that could normally affect only settings and files owned by a user. " +
        "Alternatively, an attacker with Low privileges may have the ability to cause an impact " +
        "only to non-sensitive resources.",
    "b_prh" : "The attacker is authorized with (i.e. requires) privileges that provide " +
        "significant (e.g. administrative) control over the vulnerable component that could " +
        "affect component-wide settings and files.",
    // User Interaction
    "l_ui" : "This metric captures the requirement for a user, other than the attacker, to " +
        "participate in the successful compromise of the vulnerable component. This metric " +
        "determines whether the vulnerability can be exploited solely at the will of the " +
        "attacker, or whether a separate user (or user-initiated process) must participate in " +
        "some manner.",
    "b_uin" : "The vulnerable system can be exploited without interaction from any user.",
    "b_uir" : "Successful exploitation of this vulnerability requires a user to take some action " +
        "before the vulnerability can be exploited, such as convincing a user to click a link in " +
        "an email.",
    // Scope
    "l_scp" : "An important property captured by CVSS v3.0 is the ability for a vulnerability in " +
        "one software component to impact resources beyond its means, or privileges. This " +
        "consequence is represented by the metric Authorization Scope, or simply Scope.  For more " +
        "information see the CVSSv3 Specification " +
        "(https://www.first.org/cvss/specification-document#i2.2).",
    "b_scpu" : "An exploited vulnerability can only affect resources managed by the same " +
        "authority. In this case the vulnerable component and the impacted component are the " +
        "same.",
    "b_scpc" : "An exploited vulnerability can affect resources beyond the authorization " +
        "privileges intended by the vulnerable component. In this case the vulnerable component " +
        "and the impacted component are different.",
    // Impact Metrics, Confidentiality Impact
    "l_ci" : "This metric measures the impact to the confidentiality of the information " +
        "resources managed by a software component due to a successfully exploited vulnerability. " +
        "Confidentiality refers to limiting information access and disclosure to only authorized " +
        "users, as well as preventing access by, or disclosure to, unauthorized ones.",
    "b_cin" : "There is no loss of confidentiality within the impacted component.",
    "b_cil" : "There is some loss of confidentiality. Access to some restricted information is " +
        "obtained, but the attacker does not have control over what information is obtained, or " +
        "the amount or kind of loss is constrained. The information disclosure does not cause a " +
        "direct, serious loss to the impacted component.",
    "b_cih" : "There is total loss of confidentiality, resulting in all resources within the " +
        "impacted component being divulged to the attacker. Alternatively, access to only some " +
        "restricted information is obtained, but the disclosed information presents a direct, " +
        "serious impact.",
    // Integrity Impact
    "l_ii" : "This metric measures the impact to integrity of a successfully exploited " +
        "vulnerability. Integrity refers to the trustworthiness and veracity of information.",
    "b_iin" : "There is no loss of integrity within the impacted component.",
    "b_iil" : "Modification of data is possible, but the attacker does not have control over the " +
        "consequence of a modification, or the amount of modification is constrained. The data " +
        "modification does not have a direct, serious impact on the impacted component.",
    "b_iih" : "There is a total loss of integrity, or a complete loss of protection. For " +
        "example, the attacker is able to modify any/all files protected by the impacted " +
        "component. Alternatively, only some files can be modified, but malicious modification " +
        "would present a direct, serious consequence to the impacted component.",
    // Availability Impact
    "l_ai" : "This metric measures the impact to the availability of the impacted component " +
        "resulting from a successfully exploited vulnerability. While the Confidentiality and " +
        "Integrity impact metrics apply to the loss of confidentiality or integrity of data " +
        "(e.g., information, files) used by the impacted component, this metric refers to the " +
        "loss of availability of the impacted component itself, such as a networked service " +
        "(e.g., web, database, email). Since availability refers to the accessibility of " +
        "information resources, attacks that consume network bandwidth, processor cycles, or disk " +
        "space all impact the availability of an impacted component.",
    "b_ain" : "There is no impact to availability within the impacted component.",
    "b_ail" : "There is reduced performance or interruptions in resource availability. Even if " +
        "repeated exploitation of the vulnerability is possible, the attacker does not have the " +
        "ability to completely deny service to legitimate users. The resources in the impacted " +
        "component are either partially available all of the time, or fully available only some " +
        "of the time, but overall there is no direct, serious consequence to the impacted " +
        "component.",
    "b_aih" : "There is total loss of availability, resulting in the attacker being able to " +
        "fully deny access to resources in the impacted component; this loss is either sustained " +
        "(while the attacker continues to deliver the attack) or persistent (the condition " +
        "persists even after the attack has completed). Alternatively, the attacker has the " +
        "ability to deny some availability, but the loss of availability presents a direct, " +
        "serious consequence to the impacted component (e.g., the attacker cannot disrupt " +
        "existing connections, but can prevent new connections; the attacker can repeatedly " +
        "exploit a vulnerability that, in each instance of a successful attack, leaks a only " +
        "small amount of memory, but after repeated exploitation causes a service to become " +
        "completely unavailable)."
};

// Temporal tooltips defined here
var tooltipTemp = {
    // ======================
    // Temporal Metrics Group
    // ======================
    "l_tsm" : "The Temporal metrics measure the current state of exploit techniques or code " +
        "availability, the existence of any patches or workarounds, or the confidence that one " +
        "has in the description of a vulnerability. Temporal metrics will almost certainly change " +
        "over time.",
    // Exploitability
    "l_exp" : "This metric measures the likelihood of the vulnerability being attacked, and is " +
        "typically based on the current state of exploit techniques, exploit code availability, " +
        "or active, 'in-the-wild' exploitation. The more easily a vulnerability can be exploited, " +
        "the higher the vulnerability score.",
    "b_ex" : "Assigning this value to the metric will not influence the score. It is a signal to " +
        "a scoring equation to skip this metric.",
    "b_eu" : "No exploit code is available, or an exploit is entirely theoretical.",
    "b_ep" : "Proof-of-concept exploit code is available, or an attack demonstration is not " +
        "practical for most systems. The code or technique is not functional in all situations " +
        "and may require substantial modification by a skilled attacker.",
    "b_ef" : "Functional exploit code is available. The code works in most situations where the " +
        "vulnerability exists.",
    "b_eh" : "Functional autonomous code exists, or no exploit is required (manual trigger) " +
        "and details are widely available. Exploit code works in every situation, or is actively " +
        "being delivered via an autonomous agent (such as a worm or virus). Network-connected " +
        "systems are likely to encounter scanning or exploitation attempts. Exploit development " +
        "has reached the level of reliable, widely-available, easy-to-use automated tools.",
    // Remediation Level
    "l_rl" : "The Remediation Level of a vulnerability is an important factor for " +
        "prioritization. The typical vulnerability is unpatched when initially published. " +
        "Workarounds or hotfixes may offer interim remediation until an official patch or upgrade " +
        "is issued. Each of these respective stages adjusts the temporal score downwards, " +
        "reflecting the decreasing urgency as remediation becomes final.",
    "b_rlx" : "Assigning this value to the metric will not influence the score. It is a signal " +
        "to a scoring equation to skip this metric.",
    "b_rlo" : "A complete vendor solution is available. Either the vendor has issued an official " +
        "patch, or an upgrade is available.",
    "b_rlt" : "There is an official but temporary fix available. This includes instances where " +
        "the vendor issues a temporary hotfix, tool, or workaround.",
    "b_rlw" : "There is an unofficial, non-vendor solution available. In some cases, users of " +
        "the affected technology will create a patch of their own or provide steps to work around " +
        "or otherwise mitigate the vulnerability.",
    "b_rlu" : "There is either no solution available or it is impossible to apply.",
    // Report Confidence
    "l_rc" : "This metric measures the degree of confidence in the existence of the " +
        "vulnerability and the credibility of the known technical details. Sometimes only the " +
        "existence of vulnerabilities are publicized, but without specific details. The " +
        "vulnerability may later be corroborated by research which suggests where the " +
        "vulnerability may lie, though the research may not be certain. Finally, a vulnerability " +
        "may be confirmed through acknowledgement by the author or vendor of the affected " +
        "technology.",
    "b_rcx" : "Assigning this value to the metric will not influence the score. It is a signal " +
        "to the equation to skip this metric.",
    "b_rcu" : "There are reports of impacts that indicate a vulnerability is present. The " +
        "reports indicate that the cause of the vulnerability is unknown, or reports may differ " +
        "on the cause or impacts of the vulnerability. Reporters are uncertain of the true nature " +
        "of the vulnerability, and there is little confidence in the validity of the reports or " +
        "whether a static Base score can be applied given the differences described.",
    "b_rcr" : "Significant details are published, but researchers either do not have full " +
        "confidence in the root cause, or do not have access to source code to fully confirm all " +
        "of the interactions that may lead to the result. Reasonable confidence exists, however, " +
        "that the bug is reproducible and at least one impact is able to be verified (proof-of- " +
        "concept exploits may provide this).",
    "b_rcc" : "Detailed reports exist, or functional reproduction is possible (functional " +
        "exploits may provide this). Source code is available to independently verify the " +
        "assertions of the research, or the author or vendor of the affected code has confirmed " +
        "the presence of the vulnerability."
};


var baseData = {
    av_n: { title: "AV:N", value: 0.85 }, av_a: { title: "AV:A", value: 0.62 }, av_l: { title: "AV:L", value: 0.55 }, av_p: { title: "AV:P", value: 0.2 },
    ac_l: { title: "AC:L", value: 0.77 }, ac_h: { title: "AC:H", value: 0.44 },
    pr_n: { title: "PR:N", value: 0.85 }, pr_l: { title: "PR:L", value: 0.62 }, pr_h: { title: "PR:H", value: 0.27 },
    ui_n: { title: "UI:N", value: 0.85 }, ui_r: { title: "UI:R", value: 0.62 },
    scp_u: { title: "S:U", value: 0 }, scp_c: { title: "S:C", value: 1 }, // value is boolean
    ci_n: { title: "C:N", value: 0 }, ci_l: { title: "C:L", value: 0.22 }, ci_h: { title: "C:H", value: 0.56 },
    ii_n: { title: "I:N", value: 0 }, ii_l: { title: "I:L", value: 0.22 }, ii_h: { title: "I:H", value: 0.56 },
    ai_n: { title: "A:N", value: 0 }, ai_l: { title: "A:L", value: 0.22 }, ai_h: { title: "A:H", value: 0.56 }
};

/**
 * BaseSelect object contains the actual selections (as Title strings) made by the user
 * as the buttons are chosen, along with methods to operate on the selections
 */
var baseSelect = {
    // default of empty string means, No Selection made
    av: "", ac: "", pr: "", ui: "", scp: "", ci: "", ii: "", ai: "",

    // clear the data selection values i.e. set to default values
    clearSelect: function () {
        this.av = this.ac = this.pr = this.ui = this.scp = this.ci = this.ii = this.ai = "";
    },
    // check if the base selections have been made.  ALL base selections must be made before
    // calculations are run
    isReady: function () {
        if (this.ai == "" || this.ii == "" || this.ci == "" || this.scp == "" ||
            this.ui == "" || this.pr == "" || this.ac == "" || this.av == "")
            return false;

        return true;
    },
    // get vector string for these base selections
    getVector: function () {
        return this.av + "/" + this.ac + "/" + this.pr + "/" + this.ui + "/" +
            this.scp + "/" + this.ci + "/" + this.ii + "/" + this.ai;
    }
};


/**
 * getValues() returns on object containing the base values that will be used
 * in the base score calculation.  The base values are derived from the selections
 * made.
 */
getValues = function () {
    var outValues = {};
    outValues.av = getValue('AV:'+$('#AV')[0].value);
    outValues.ac = getValue('AC:'+$('#AC')[0].value);
    outValues.pr = getValue('PR:'+$('#PR')[0].value);
    outValues.scp = getValue('S:'+$('#S')[0].value);
    //value of PR can change based on Scope selection (special case), see spec
    if (outValues.scp) {
        if ($('#PR')[0].value == 'L') {
            outValues.pr = 0.68;
            //alert("pr changed to .68");
        }
        if ($('#PR')[0].value == 'H') {
            outValues.pr = 0.50;
            // alert("pr changed to .50");
        }
    }
    outValues.ui = getValue('UI:'+$('#UI')[0].value);
    outValues.ci = getValue('C:'+$('#C')[0].value);
    outValues.ii = getValue('I:'+$('#I')[0].value);
    outValues.ai = getValue('A:'+$('#A')[0].value);

    return outValues;
};


/**
 * Get a numeric value from the data map above based on a title string
 * @param title
 * @returns {*}
 */
var getValue = function (title) {
    return getEntry(title).value;
};

/**
 * Get an entry from the baseData structure based on vector title.
 * @param title
 * @returns {*}
 */
var getEntry = function (title) {
    var keys = Object.keys(baseData);
    for (var i = 0; i < keys.length; i++) {
        var entry = baseData[keys[i]];
        if (entry.title == title) {
            return entry;
        }
    }
    alert("BaseData: No Entry for title: " + title);
};


// Rounds up to nearest tenth, as per spec.
function roundUp(score) {
    // multiple by 10, round using ceil function, divide by 10
    return Math.ceil(score * 10) / 10;
}

calculateCVSS3 = function() {
    // compute impact subscore:  Spec: Impact = 1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact)
    var baseValues = getValues();
    var impactSub = 1.0 - (1.0 - baseValues.ci) * (1.0 - baseValues.ii) * (1.0 - baseValues.ai);

    var result = {};
    result.debugStr = "impactSubScore: " + impactSub + "\n";
    
    // compute exploit score
    // Spec: Exploitability = 8.22 * AttackVector*AttackComplexity*PrivRequired*UserInteract
    result.exploitScore = 8.22 * baseValues.av * baseValues.ac * baseValues.pr * baseValues.ui;
    result.debugStr += "exploitScore: " + result.exploitScore + "\n";

    // calculations are different based on the Scope selection
    result.debugstr += "scope: " + baseValues.scp + "\n";
    if (!baseValues.scp)  // scope is Unchanged
    {
        result.impactScore = 6.42 * impactSub;
        result.baseScore = result.impactScore + result.exploitScore;
    }
    else    // scope is Changed
    {
        result.impactScore = 7.52 * (impactSub - 0.029) - 3.25 * Math.pow(impactSub - 0.02, 15);
        result.baseScore = 1.08 * (result.impactScore + result.exploitScore);
    }
    result.debugStr += "impactScore: " + result.impactScore + "\n";

    if (result.impactScore <= 0) {
        result.baseScore = 0;
        result.impactScore = 0;
    }
    else {
        result.baseScore = roundUp(result.baseScore);
        if (result.baseScore > 10)
            result.baseScore = 10;
    }

    result.debugStr += "baseScore: " + result.baseScore + "\n";
    return result.baseScore;
}




Template.edit_cvss3.events({
    'change select': function(event, instance) {
        var score = calculateCVSS3();
        Template.parentData().score = score;
        Template.parentData().cvss3[event.target.className].value=event.target.value;
        vulnDeps.changed();
    },
    'keyup textarea': function(event, instance) {
        console.log(event.target);
        Template.parentData().cvss3[event.target.className].comment = event.target.value;
        vulnDeps.changed();
    },
});

Handlebars.registerHelper('getvalue', function (o) {
    return JSON.stringify(o);
});




Template.edit_cvss3.helpers({
    getSelected: function(cvss3, metric, val) {
        if (cvss3[metric].value===val) return "selected";
        return "";
    },
    getComment: function(cvss3, metric) {
        return cvss3[metric].comment;
    },
    metrics: function() {
        return [
            {
                id: "AV",
                name: TAPi18n.__('av'),
                description: cvss3_tips.l_av,
                values: [
                    { text: TAPi18n.__('network'), value: "N", description: cvss3_tips.b_avn },
                    { text: TAPi18n.__('adj_net'), value: "A", description: cvss3_tips.b_ava },
                    { text: TAPi18n.__('local'), value: "L", description: cvss3_tips.b_avl },
                    { text: TAPi18n.__('physical'), value: "P", description: cvss3_tips.b_avp }
                ]
            },
            {
                id: "AC",
                name: TAPi18n.__('ac'),
                description: cvss3_tips.l_ac,
                values: [
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_acl },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_ach },
                ]
            },
            {
                id: "PR",
                name: TAPi18n.__('pr'),
                description: cvss3_tips.l_av,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_prn },
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_prl },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_prh },
                ]
            },
            {
                id: "UI",
                name: TAPi18n.__('ui'),
                description: cvss3_tips.l_ui,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_uin },
                    { text: TAPi18n.__('required'), value: "R", description: cvss3_tips.b_uir },
                ]
            },
            {
                id: "S",
                name: TAPi18n.__('s'),
                description: cvss3_tips.l_scp,
                values: [
                    { text: TAPi18n.__('unchanged'), value: "U", description: cvss3_tips.b_scpu },
                    { text: TAPi18n.__('changed'), value: "C", description: cvss3_tips.b_scpc },
                ]
            },
            {
                id: "C",
                name: TAPi18n.__('ci'),
                description: cvss3_tips.l_ci,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_cin },
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_cil },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_cih },
                ]
            },
            {
                id: "I",
                name: TAPi18n.__('ii'),
                description: cvss3_tips.l_ii,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_iin },
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_iil },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_iih },
                ]
            },
            {
                id: "A",
                name: TAPi18n.__('ai'),
                description: cvss3_tips.l_ai,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_ain },
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_ail },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_aih },
                ]
            },
        ];
    }
});


Template.cvss3.helpers({
    getSelectedText: function(cvss3, metric, val, text) {
        if (cvss3[metric].value===val) return text;
        return "";
    },
    getComment: function(cvss3, metric) {
        return cvss3[metric].comment;
    },
    metrics: function() {
        return [
            {
                id: "AV",
                name: TAPi18n.__('av'),
                description: cvss3_tips.l_av,
                values: [
                    { text: TAPi18n.__('network'), value: "N", description: cvss3_tips.b_avn },
                    { text: TAPi18n.__('adj_net'), value: "A", description: cvss3_tips.b_ava },
                    { text: TAPi18n.__('local'), value: "L", description: cvss3_tips.b_avl },
                    { text: TAPi18n.__('physical'), value: "P", description: cvss3_tips.b_avp }
                ]
            },
            {
                id: "AC",
                name: TAPi18n.__('ac'),
                description: cvss3_tips.l_ac,
                values: [
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_acl },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_ach },
                ]
            },
            {
                id: "PR",
                name: TAPi18n.__('pr'),
                description: cvss3_tips.l_av,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_prn },
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_prl },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_prh },
                ]
            },
            {
                id: "UI",
                name: TAPi18n.__('ui'),
                description: cvss3_tips.l_ui,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_uin },
                    { text: TAPi18n.__('required'), value: "R", description: cvss3_tips.b_uir },
                ]
            },
            {
                id: "S",
                name: TAPi18n.__('s'),
                description: cvss3_tips.l_scp,
                values: [
                    { text: TAPi18n.__('unchanged'), value: "U", description: cvss3_tips.b_scpu },
                    { text: TAPi18n.__('changed'), value: "C", description: cvss3_tips.b_scpc },
                ]
            },
            {
                id: "C",
                name: TAPi18n.__('ci'),
                description: cvss3_tips.l_ci,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_cin },
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_cil },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_cih },
                ]
            },
            {
                id: "I",
                name: TAPi18n.__('ii'),
                description: cvss3_tips.l_ii,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_iin },
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_iil },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_iih },
                ]
            },
            {
                id: "A",
                name: TAPi18n.__('ai'),
                description: cvss3_tips.l_ai,
                values: [
                    { text: TAPi18n.__('none'), value: "N", description: cvss3_tips.b_ain },
                    { text: TAPi18n.__('low'), value: "L", description: cvss3_tips.b_ail },
                    { text: TAPi18n.__('high'), value: "H", description: cvss3_tips.b_aih },
                ]
            },
        ];
    }
});
