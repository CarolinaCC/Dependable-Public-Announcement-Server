package dpas.common.domain;

import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.InvalidNumberOfPostsException;
import java.util.ArrayList;

public class GeneralBoard implements AnnouncementBoard {
    public ArrayList<Post> posts;

    @Override
    public void post(User user, Post post) throws NullPostException, NullUserException {
        checkArguments(user, post);
        posts.add(post);
    }

    public void checkArguments(User user, Post post) throws NullUserException, NullPostException  {
        if (user == null) {
            throw new NullUserException();
        }
        if (post == null) {
            throw new NullPostException();
        }
    }

    @Override
    public Post[] read(int number) throws InvalidNumberOfPostsException {
        if (number <= 0 || number > posts.size())
            throw new InvalidNumberOfPostsException();
        return (Post[]) posts.subList(posts.size()-number, posts.size()).toArray();
    }
}
