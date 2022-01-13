import python_rules


class DeleteFromOtherMailbox(python_rules.rule.Rule):
    id = "5a657bf6-5f9c-4c57-8794-ede619f2e674"
    title = "Delete from other user's mailbox"
    description = "Mailbox item deleted by a user other than a mailbox owner"
    author = "Florentijn Knol"


    def rule(self, e):
        try:
            return (e["Operation"] == "HardDelete" or e["Operation"] == "SoftDelete") and \
                   (e["UserId"] != e["MailboxOwnerUPN"])
        except KeyError:
            return False