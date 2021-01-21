@Library('dst-shared@release/shasta-1.4') _

dockerBuildPipeline {
    app = "conman"
    name = "conman"
    description = "Cray Management System conman logging service"
    repository = "cray"
    imagePrefix = "cray"
    product = "csm"
    
    githubPushRepo = "Cray-HPE/cms-conman"
    /*
        By default all branches are pushed to GitHub

        Optionally, to limit which branches are pushed, add a githubPushBranches regex variable
        Examples:
        githubPushBranches =  /master/ # Only push the master branch
        
        In this case, we push bugfix, feature, hot fix, master, and release branches
    */
    githubPushBranches =  /(bugfix\/.*|feature\/.*|hotfix\/.*|master|release\/.*)/ 
}
