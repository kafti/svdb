import logging
import sqlite3
import os.path

from svdb.id.cpe import CPEID
from svdb.id.cve import CVEID


logger = logging.getLogger("svdb.vuln.db_reader")
logger.setLevel(logging.INFO)


class DB(object):
    """DB layer
    """
    
    @classmethod
    def init(cls, db_path='vuln.sqlite'):
        if db_path == 'vuln.sqlite':
            cls._db_path = os.path.join(os.path.dirname(__file__), db_path)
        else:
            cls._db_path = db_path
        
        cls._con = sqlite3.connect(cls._db_path)
        cls._con.row_factory = sqlite3.Row
        cls._cur = cls._con.cursor()
        logger.debug("Opened DB: %s" % cls._db_path)
        
    @classmethod
    def get_cpe_by_cve(cls, cve_id):
        """ Return list of CPEID by CVE-ID
        @param cve_id: string with CVE-ID or CVEID instance
        @return: list of tuples (CPEID instance, Official name) 
        """
        
        if not isinstance(cve_id, CVEID):
            cve_id = CVEID(cve_id)
        
        sql = """
                SELECT pr.part, pr.vendor, pr.product, concr_pr.version,
                        concr_pr.pr_update, concr_pr.edition, concr_pr.language,
                        pr.official_name
                FROM vulnerabilities AS vulns
                JOIN products_to_vulnerabilities AS pr2vulns ON pr2vulns.vuln_id = vulns.id
                JOIN concrete_products AS concr_pr ON concr_pr.id = pr2vulns.concrete_product_id
                JOIN products AS pr ON pr.id = concr_pr.product_id
                WHERE cve_id='%s'
                """ % cve_id
        
        res = cls._cur.execute(sql).fetchall()
        
        ret = []
        for row in res:
            cpeid = CPEID('', row['part'], row['vendor'], row['product'],
                          row['version'], row['pr_update'],
                          row['edition'], row['language'])
            ret.append((cpeid, row['official_name']))
        
        return ret
    
if __name__ == '__main__':
    DB.init()
    for cpe in DB.get_cpe_by_cve('CVE-2010-4051'):
        print str(cpe[0]), cpe[1]
