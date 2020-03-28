package dpas.common.domain;

import dpas.common.domain.exception.NullAnnouncementException;

public class GeneralBoard extends AnnouncementBoard {

    public static final String GENERAL_BOARD_IDENTIFIER = "DPAS-GENERAL-BOARD";

    @Override
    public synchronized void post(Announcement announcement) throws NullAnnouncementException {
        if (announcement == null) {
            throw new NullAnnouncementException("Invalid Announcement: Cannot be null");
        }
        _posts.add(announcement);

    }

    @Override
    public String getIdentifier() {
        return GENERAL_BOARD_IDENTIFIER;
    }

}
