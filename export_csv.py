import csv


class ToCsv:
    @staticmethod
    def export_csv(fich, fieldnames, data):

        with open(fich, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)