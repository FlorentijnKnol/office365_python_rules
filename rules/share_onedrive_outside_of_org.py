import python_rules

class ShareOneDriveOutsideOrg(python_rules.rule.Rule):
    id = "8f495b9d-761a-4a6f-bb59-6608dc125dfc"
    title = "Share OneDrive Items outside of organization"
    description = "Useful to detect individuals voluntarily sharing confidential information with external party"
    author = "Florentijn Knol"


    def rule(self, e):
        try:
            safe_mail_exts = [
                "headfirst.nl",
                "staffingms.com",
                "between.com",
                "headfirst.onmicrosoft.com",
                "sharepoint"]
            return (e["Operation"] == "AddedToSecureLink" and e["UserId"].split("@")[1].lower() not in safe_mail_exts)
        except KeyError:
            return False
        except IndexError:
            return False